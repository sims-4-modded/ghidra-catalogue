/******************************************************************************
 * Copyright (c) 2026 Sims 4 mods developers
 *****************************************************************************/
// Serve the open program over HTTP on 127.0.0.1, without the Ghidra GUI, with the endpoints and answer formats that
// the GhidraMCP bridge (bridge_mcp_ghidra.py) and tools/ghidra-catalogue/ghcat.py use.
// Run it as the post-script of analyzeHeadless with -process (tools/ghidra/ghidra-server.bat). Arguments: the port
// (8083 by default) and the build in the project (<module>_<version>). The /build endpoint tells the clients which
// build the server serves. The script stops when a client calls /shutdown; it then saves the changes to the program.
// The server also makes byte signatures (/signature) and finds them (/find_bytes), so that a hook can find a function
// again after a game update.
//@category Sims4

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class Ts4McpServer extends GhidraScript {

	private static final int DEFAULT_PORT = 8083;
	private static final int DECOMPILE_TIMEOUT_SECONDS = 120;

	private final CountDownLatch stopSignal = new CountDownLatch(1);
	private DecompInterface decompiler;
	private String build = "unknown";
	/// The longest signature that /signature makes.
	private static final int MAX_SIGNATURE = 96;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
		if (args.length > 1 && !args[1].isEmpty()) {
			build = args[1];
		}

		// GhidraScript starts a transaction before it runs the script. While a transaction is open, the program
		// cannot save its changes, thus each change failed. Close the transaction of the script. Each change then
		// uses its own transaction and saves the program.
		end(true);

		decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);

		HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
		// One thread: the program and the decompiler get one request at a time.
		server.setExecutor(null);
		addGet(server, "/build", q -> buildInfo());
		addGet(server, "/methods", q -> page(functionNames(), q));
		addGet(server, "/list_functions", q -> String.join("\n", functionLines()));
		addGet(server, "/classes", q -> page(classNames(), q));
		addGet(server, "/namespaces", q -> page(namespaceNames(), q));
		addGet(server, "/segments", q -> page(segmentLines(), q));
		addGet(server, "/imports", q -> page(externalLines(), q));
		addGet(server, "/exports", q -> page(exportLines(), q));
		addGet(server, "/data", q -> page(dataLines(), q));
		addGet(server, "/strings", q -> page(stringLines(q.getOrDefault("filter", "")), q));
		addGet(server, "/searchFunctions", q -> page(searchFunctions(q.getOrDefault("query", "")), q));
		addGet(server, "/get_function_by_address", q -> functionInfo(q.get("address")));
		addGet(server, "/decompile_function", q -> decompileAt(q.get("address")));
		addGet(server, "/disassemble_function", q -> disassembleAt(q.get("address")));
		addGet(server, "/xrefs_to", q -> page(xrefsTo(q.get("address")), q));
		addGet(server, "/xrefs_from", q -> page(xrefsFrom(q.get("address")), q));
		addGet(server, "/function_xrefs", q -> page(functionXrefs(q.getOrDefault("name", "")), q));
		addGet(server, "/get_current_address", q -> "There is no GUI: the headless server has no current address.");
		addGet(server, "/get_current_function", q -> "There is no GUI: the headless server has no current function.");
		addPost(server, "/decompile", body -> decompileByName(body.trim()));
		addPost(server, "/renameFunction", body -> renameFunction(form(body)));
		addPost(server, "/rename_function_by_address", body -> renameFunctionAt(form(body)));
		addPost(server, "/set_decompiler_comment", body -> setComment(form(body), CodeUnit.PRE_COMMENT));
		addPost(server, "/set_disassembly_comment", body -> setComment(form(body), CodeUnit.EOL_COMMENT));
		addGet(server, "/signature", q -> signatureAt(q.get("address")));
		addGet(server, "/find_bytes", q -> page(findBytes(q.getOrDefault("pattern", "")), q));
		addPost(server, "/shutdown", body -> {
			stopSignal.countDown();
			return "The server stops.";
		});
		server.start();
		println("Ts4McpServer listens on 127.0.0.1:" + port + " for " + currentProgram.getName() + ", build " + build +
			", project " + projectFolder());

		while (!stopSignal.await(1, java.util.concurrent.TimeUnit.SECONDS)) {
			if (monitor.isCancelled()) {
				break;
			}
		}
		server.stop(0);
		decompiler.dispose();
		println("Ts4McpServer stopped");
	}

	// ---- HTTP -------------------------------------------------------------------------------------------------

	private void addGet(HttpServer server, String path, Handler<Map<String, String>> handler) {
		server.createContext(path, exchange -> respond(exchange, () -> handler.apply(query(exchange))));
	}

	private void addPost(HttpServer server, String path, Handler<String> handler) {
		server.createContext(path, exchange -> respond(exchange, () -> handler.apply(body(exchange))));
	}

	/// A request handler that may throw. The server turns an exception into an error answer.
	private interface Handler<T> {
		String apply(T input) throws Exception;
	}

	private interface Answer {
		String get() throws Exception;
	}

	private void respond(HttpExchange exchange, Answer answer) throws IOException {
		String text;
		int status = 200;
		try {
			text = answer.get();
		}
		catch (Exception error) {
			text = "Error: " + error;
			status = 500;
		}
		byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
		exchange.sendResponseHeaders(status, bytes.length);
		try (OutputStream out = exchange.getResponseBody()) {
			out.write(bytes);
		}
	}

	private static Map<String, String> query(HttpExchange exchange) {
		return form(exchange.getRequestURI().getRawQuery());
	}

	private static String body(HttpExchange exchange) throws IOException {
		try (InputStream in = exchange.getRequestBody()) {
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
	}

	private static Map<String, String> form(String text) {
		Map<String, String> values = new HashMap<>();
		if (text == null || text.isEmpty()) {
			return values;
		}
		for (String pair : text.split("&")) {
			int equals = pair.indexOf('=');
			String key = URLDecoder.decode(equals < 0 ? pair : pair.substring(0, equals), StandardCharsets.UTF_8);
			String value = equals < 0 ? "" : URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8);
			values.put(key, value);
		}
		return values;
	}

	private static String page(List<String> lines, Map<String, String> query) {
		int offset = Integer.parseInt(query.getOrDefault("offset", "0"));
		int limit = Integer.parseInt(query.getOrDefault("limit", "100"));
		int start = Math.max(0, Math.min(offset, lines.size()));
		int end = Math.max(start, Math.min(lines.size(), start + limit));
		return String.join("\n", lines.subList(start, end));
	}

	// ---- The build ----------------------------------------------------------------------------------------------

	private String projectFolder() {
		return currentProgram.getDomainFile().getProjectLocator().getProjectDir().getParent();
	}

	/// The build that the server serves, as JSON: the build, the program and the hash of the imported file.
	private String buildInfo() {
		return "{\"build\": \"" + json(build) + "\", \"program\": \"" + json(currentProgram.getName()) +
			"\", \"executable_sha256\": \"" + json(String.valueOf(currentProgram.getExecutableSHA256())) +
			"\", \"executable_path\": \"" + json(String.valueOf(currentProgram.getExecutablePath())) +
			"\", \"project\": \"" + json(projectFolder()) + "\", \"image_base\": \"" + currentProgram.getImageBase() +
			"\"}";
	}

	private static String json(String text) {
		return text.replace("\\", "\\\\").replace("\"", "\\\"");
	}

	// ---- Lists ------------------------------------------------------------------------------------------------

	private List<String> functionNames() {
		List<String> names = new ArrayList<>();
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			names.add(function.getName());
		}
		return names;
	}

	private List<String> functionLines() {
		List<String> lines = new ArrayList<>();
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			lines.add(function.getName() + " at " + function.getEntryPoint());
		}
		return lines;
	}

	private List<String> classNames() {
		List<String> names = new ArrayList<>();
		Iterator<? extends Namespace> classes = currentProgram.getSymbolTable().getClassNamespaces();
		while (classes.hasNext()) {
			names.add(classes.next().getName(true));
		}
		names.sort(String::compareTo);
		return names;
	}

	private List<String> namespaceNames() {
		List<String> names = new ArrayList<>();
		for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
			Namespace parent = symbol.getParentNamespace();
			if (parent != null && !parent.isGlobal()) {
				names.add(parent.getName(true));
			}
		}
		return names.stream().distinct().sorted().toList();
	}

	private List<String> segmentLines() {
		List<String> lines = new ArrayList<>();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			lines.add(block.getName() + ": " + block.getStart() + " - " + block.getEnd());
		}
		return lines;
	}

	private List<String> externalLines() {
		List<String> lines = new ArrayList<>();
		for (Symbol symbol : currentProgram.getSymbolTable().getExternalSymbols()) {
			lines.add(symbol.getName() + " -> " + symbol.getAddress());
		}
		return lines;
	}

	private List<String> exportLines() {
		List<String> lines = new ArrayList<>();
		SymbolTable table = currentProgram.getSymbolTable();
		for (Address address : table.getExternalEntryPointIterator()) {
			Symbol symbol = table.getPrimarySymbol(address);
			lines.add((symbol != null ? symbol.getName() : "?") + " -> " + address);
		}
		return lines;
	}

	private List<String> dataLines() {
		List<String> lines = new ArrayList<>();
		for (Data data : currentProgram.getListing().getDefinedData(true)) {
			String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
			lines.add(data.getAddress() + ": " + label + " = " + data.getDefaultValueRepresentation());
		}
		return lines;
	}

	private List<String> stringLines(String filter) {
		List<String> lines = new ArrayList<>();
		for (Data data : currentProgram.getListing().getDefinedData(true)) {
			if (!StringDataInstance.isString(data)) {
				continue;
			}
			String value = StringDataInstance.getStringDataInstance(data).getStringValue();
			if (value != null && (filter.isEmpty() || value.toLowerCase().contains(filter.toLowerCase()))) {
				lines.add(data.getAddress() + ": \"" + value.replace("\n", "\\n") + "\"");
			}
		}
		return lines;
	}

	private List<String> searchFunctions(String text) {
		List<String> lines = new ArrayList<>();
		String needle = text.toLowerCase();
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			if (function.getName().toLowerCase().contains(needle)) {
				lines.add(function.getName() + " @ " + function.getEntryPoint());
			}
		}
		return lines;
	}

	// ---- Signatures -------------------------------------------------------------------------------------------

	private List<MemoryBlock> codeBlocks() {
		List<MemoryBlock> blocks = new ArrayList<>();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (block.isExecute() && block.isInitialized()) {
				blocks.add(block);
			}
		}
		return blocks;
	}

	/// The addresses in the code where the bytes match the mask, up to a limit.
	private List<Address> matches(byte[] bytes, byte[] masks, int limit) throws Exception {
		List<Address> found = new ArrayList<>();
		for (MemoryBlock block : codeBlocks()) {
			Address from = block.getStart();
			while (from != null && found.size() < limit) {
				Address hit = currentProgram.getMemory().findBytes(from, block.getEnd(), bytes, masks, true, monitor);
				if (hit == null) {
					break;
				}
				found.add(hit);
				from = hit.next();
			}
		}
		return found;
	}

	private static String patternText(byte[] bytes, byte[] masks, int count) {
		StringBuilder text = new StringBuilder();
		for (int i = 0; i < count; i++) {
			if (i > 0) {
				text.append(' ');
			}
			text.append(masks[i] == 0 ? "??" : String.format("%02X", bytes[i] & 0xFF));
		}
		return text.toString();
	}

	/// The shortest byte signature from the start of the function that occurs once in the code. Each operand that
	/// refers to an address outside the function is a wildcard, because the linker can move that address.
	private String signatureAt(String text) throws Exception {
		Function function = functionAt(text);
		if (function == null) {
			return "No function at " + text;
		}
		long start = function.getEntryPoint().getOffset();
		long end = function.getBody().getMaxAddress().getOffset();
		byte[] bytes = new byte[MAX_SIGNATURE];
		byte[] masks = new byte[MAX_SIGNATURE];
		int count = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			byte[] code = instruction.getBytes();
			byte[] mask = new byte[code.length];
			Arrays.fill(mask, (byte) 0xFF);
			for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
				boolean outside = false;
				for (Reference reference : instruction.getOperandReferences(operand)) {
					if (!reference.getToAddress().isMemoryAddress()) {
						continue; // A stack offset stays the same when the linker moves the code.
					}
					long to = reference.getToAddress().getOffset();
					outside |= to < start || to > end;
				}
				if (!outside) {
					continue;
				}
				byte[] value = instruction.getPrototype().getOperandValueMask(operand).getBytes();
				for (int i = 0; i < Math.min(value.length, mask.length); i++) {
					if (value[i] != 0) {
						mask[i] = 0;
					}
				}
			}
			if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				// A relative call or jump to another function: the last four bytes are the distance.
				for (Address flow : instruction.getFlows()) {
					long to = flow.getOffset();
					if ((to < start || to > end) && code.length >= 5) {
						for (int i = code.length - 4; i < code.length; i++) {
							mask[i] = 0;
						}
					}
				}
			}
			for (int i = 0; i < code.length && count < MAX_SIGNATURE; i++, count++) {
				bytes[count] = code[i];
				masks[count] = mask[i];
			}
			if (count >= 8 && matches(Arrays.copyOf(bytes, count), Arrays.copyOf(masks, count), 2).size() == 1) {
				return "unique " + count + " " + patternText(bytes, masks, count);
			}
			if (count >= MAX_SIGNATURE) {
				break;
			}
		}
		return "not unique " + count + " " + patternText(bytes, masks, count);
	}

	/// The addresses where a pattern such as "48 8B ?? 05" occurs in the code.
	private List<String> findBytes(String pattern) throws Exception {
		String[] parts = pattern.trim().split("\\s+");
		byte[] bytes = new byte[parts.length];
		byte[] masks = new byte[parts.length];
		for (int i = 0; i < parts.length; i++) {
			if (parts[i].equals("??") || parts[i].equals("?")) {
				continue;
			}
			bytes[i] = (byte) Integer.parseInt(parts[i], 16);
			masks[i] = (byte) 0xFF;
		}
		List<String> lines = new ArrayList<>();
		for (Address hit : matches(bytes, masks, 100)) {
			Function function = currentProgram.getFunctionManager().getFunctionAt(hit);
			lines.add(hit + (function != null ? " " + function.getName() : ""));
		}
		return lines;
	}

	// ---- One function -----------------------------------------------------------------------------------------

	private Function functionAt(String text) {
		Address address = currentProgram.getAddressFactory().getAddress(text);
		if (address == null) {
			return null;
		}
		Function function = currentProgram.getFunctionManager().getFunctionAt(address);
		return function != null ? function : currentProgram.getFunctionManager().getFunctionContaining(address);
	}

	private String functionInfo(String text) {
		Function function = functionAt(text);
		if (function == null) {
			return "No function at " + text;
		}
		return "Function: " + function.getName() + " at " + function.getEntryPoint() + "\n" + "Signature: " +
			function.getSignature() + "\n" + "Entry: " + function.getEntryPoint() + "\n" + "Body: " +
			function.getBody().getMinAddress() + " - " + function.getBody().getMaxAddress();
	}

	private String decompile(Function function) {
		DecompileResults results = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
		if (results == null || !results.decompileCompleted()) {
			return "Decompile failed: " + (results != null ? results.getErrorMessage() : "no result");
		}
		return results.getDecompiledFunction().getC();
	}

	private String decompileAt(String text) {
		Function function = functionAt(text);
		return function == null ? "No function at " + text : decompile(function);
	}

	private String decompileByName(String name) {
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			if (function.getName().equals(name)) {
				return decompile(function);
			}
		}
		return "No function named " + name;
	}

	private String disassembleAt(String text) {
		Function function = functionAt(text);
		if (function == null) {
			return "No function at " + text;
		}
		StringBuilder lines = new StringBuilder();
		Listing listing = currentProgram.getListing();
		for (Instruction instruction : listing.getInstructions(function.getBody(), true)) {
			String comment = instruction.getComment(CodeUnit.EOL_COMMENT);
			lines.append(instruction.getAddress()).append(": ").append(instruction);
			if (comment != null) {
				lines.append(" ; ").append(comment);
			}
			lines.append("\n");
		}
		return lines.toString();
	}

	private String referenceLine(Address from, Reference reference) {
		Function function = currentProgram.getFunctionManager().getFunctionContaining(from);
		return "From " + from + (function != null ? " in " + function.getName() : "") + " [" +
			reference.getReferenceType().getName() + "]";
	}

	private List<String> xrefsTo(String text) {
		List<String> lines = new ArrayList<>();
		Address address = currentProgram.getAddressFactory().getAddress(text);
		if (address == null) {
			return lines;
		}
		for (Reference reference : currentProgram.getReferenceManager().getReferencesTo(address)) {
			lines.add(referenceLine(reference.getFromAddress(), reference));
		}
		return lines;
	}

	private List<String> xrefsFrom(String text) {
		List<String> lines = new ArrayList<>();
		Address address = currentProgram.getAddressFactory().getAddress(text);
		if (address == null) {
			return lines;
		}
		for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(address)) {
			Function target = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
			lines.add("To " + reference.getToAddress() + (target != null ? " to " + target.getName() : "") + " [" +
				reference.getReferenceType().getName() + "]");
		}
		return lines;
	}

	private List<String> functionXrefs(String name) {
		List<String> lines = new ArrayList<>();
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			if (function.getName().equals(name)) {
				lines.addAll(xrefsTo(function.getEntryPoint().toString()));
			}
		}
		return lines;
	}

	// ---- Changes ----------------------------------------------------------------------------------------------

	private interface Change {
		String apply() throws Exception;
	}

	/// Make one change in a transaction, and save the program, so that the change stays if the server stops.
	private String change(String description, Change work) throws Exception {
		int transaction = currentProgram.startTransaction(description);
		boolean done = false;
		try {
			String answer = work.apply();
			done = true;
			return answer;
		}
		finally {
			currentProgram.endTransaction(transaction, done);
			if (done) {
				currentProgram.getDomainFile().save(monitor);
			}
		}
	}

	private String renameFunction(Map<String, String> values) throws Exception {
		String oldName = values.getOrDefault("oldName", "");
		String newName = values.getOrDefault("newName", "");
		return change("Rename function", () -> {
			for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
				if (function.getName().equals(oldName)) {
					function.setName(newName, SourceType.USER_DEFINED);
					return "Renamed successfully";
				}
			}
			return "No function named " + oldName;
		});
	}

	private String renameFunctionAt(Map<String, String> values) throws Exception {
		Function function = functionAt(values.getOrDefault("function_address", ""));
		if (function == null) {
			return "No function at " + values.get("function_address");
		}
		String newName = values.getOrDefault("new_name", "");
		return change("Rename function", () -> {
			function.setName(newName, SourceType.USER_DEFINED);
			return "Function renamed successfully";
		});
	}

	private String setComment(Map<String, String> values, int type) throws Exception {
		Address address = currentProgram.getAddressFactory().getAddress(values.getOrDefault("address", ""));
		if (address == null) {
			return "No address " + values.get("address");
		}
		String comment = values.getOrDefault("comment", "");
		return change("Set comment", () -> {
			currentProgram.getListing().setComment(address, type, comment);
			return "Comment set successfully";
		});
	}
}
