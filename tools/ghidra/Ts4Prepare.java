/******************************************************************************
 * Copyright (c) 2026 Sims 4 mods developers
 *****************************************************************************/
// Prepare a module of The Sims 4 for the catalogue. The script has two modes.
// - rebase: move the image base to 0x0, so that each address is an RVA. Run it as the pre-script of the import.
// - name <names.tsv>: name the functions from the MSVC RTTI and from the Python method tables, then write the name
//   of each named function to names.tsv. Run it as the post-script, after the analysis.
// The game has no symbols. RTTI gives the names of the classes and their vtables. A Python method table gives the
// Python name of each C function that a native module or a native type shows to the game Python.
//@category Sims4

import java.io.BufferedWriter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class Ts4Prepare extends GhidraScript {

	/// The size of one PyMethodDef on x64: the name, the C function, the flags (with padding) and the text.
	private static final int METHOD_DEF_SIZE = 32;
	/// The position of m_methods in PyModuleDef, and of m_name.
	private static final int MODULE_METHODS = 64;
	private static final int MODULE_NAME = 40;
	/// The position of tp_methods in PyTypeObject of Python 3.7, and of tp_name.
	private static final int TYPE_METHODS = 232;
	private static final int TYPE_NAME = 24;
	/// The slot id Py_tp_methods in a PyType_Spec slot list.
	private static final long SLOT_TP_METHODS = 64;
	/// All the METH_ flags of Python 3.7.
	private static final int METHOD_FLAGS = 0xFF;
	private static final int MAX_NAME = 128;

	/// The PE base relocation of a 64-bit pointer.
	private static final int IMAGE_REL_BASED_DIR64 = 10;
	private static final String OPTIONS = "Ts4Prepare";
	private static final String ORIGINAL_BASE = "Original image base";

	private Memory memory;
	private long originalBase = 0;
	private final List<MemoryBlock> code = new ArrayList<>();
	private final List<MemoryBlock> data = new ArrayList<>();

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String mode = args.length > 0 ? args[0] : "";
		if (mode.equals("rebase")) {
			rebase();
			return;
		}
		if (!mode.equals("name") || args.length != 2) {
			printerr("Give the mode: rebase, or name <path of names.tsv>.");
			return;
		}
		if (currentProgram.getImageBase().getOffset() != 0) {
			printerr("The image base is " + currentProgram.getImageBase() + ", not 0x0. Run the mode rebase first.");
			return;
		}
		memory = currentProgram.getMemory();
		originalBase = currentProgram.getOptions(OPTIONS).getLong(ORIGINAL_BASE, 0);
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized()) {
				continue;
			}
			(block.isExecute() ? code : data).add(block);
		}
		int classes = nameFromRtti();
		int[] python = nameFromMethodTables();
		int written = writeNames(Path.of(args[1]));
		println("Ts4Prepare: RTTI classes " + classes + ", vtables named " + vtablesNamed + ", virtual functions " +
			"named " + virtualsNamed + "; Python method tables " + python[0] + ", Python functions named " +
			python[1] + "; names.tsv lines " + written);
	}

	private void rebase() throws Exception {
		long old = currentProgram.getImageBase().getOffset();
		if (old != 0) {
			println("Move the image base from " + currentProgram.getImageBase() + " to 0x0");
			// The pointers in the data can keep the old base. Keep the old base, so that the mode name can read them.
			currentProgram.getOptions(OPTIONS).setLong(ORIGINAL_BASE, old);
			currentProgram.setImageBase(toAddr(0), true);
			correctPointers(old);
		}
	}

	/// Ghidra moves the blocks, but each pointer that a base relocation wrote keeps the old base. Write each such
	/// pointer again as an RVA, so that the analysis follows the pointers of the vtables and of the tables.
	private void correctPointers(long old) throws Exception {
		Memory mem = currentProgram.getMemory();
		int corrected = 0;
		int skipped = 0;
		Iterator<Relocation> relocations = currentProgram.getRelocationTable().getRelocations();
		while (relocations.hasNext()) {
			Relocation relocation = relocations.next();
			if (relocation.getType() != IMAGE_REL_BASED_DIR64) {
				skipped++;
				continue;
			}
			Address at = relocation.getAddress();
			try {
				long value = mem.getLong(at);
				if (Long.compareUnsigned(value, old) >= 0) {
					mem.setLong(at, value - old);
					corrected++;
				}
			}
			catch (Exception error) {
				skipped++;
			}
		}
		println("Pointers written as RVAs: " + corrected + ", relocations not changed: " + skipped);
	}

	/// The RVA of a pointer in the data. A pointer can have the RVA or the address at the original image base.
	private long pointer(long value) {
		if (originalBase != 0 && value >= originalBase && !inCode(value) && !inData(value)) {
			return value - originalBase;
		}
		return value;
	}

	// ---- Memory ----------------------------------------------------------------------------------------------

	private boolean inCode(long value) {
		for (MemoryBlock block : code) {
			if (value >= block.getStart().getOffset() && value <= block.getEnd().getOffset()) {
				return true;
			}
		}
		return false;
	}

	private boolean inData(long value) {
		for (MemoryBlock block : data) {
			if (value >= block.getStart().getOffset() && value <= block.getEnd().getOffset()) {
				return true;
			}
		}
		return false;
	}

	/// The bytes of one block, little endian.
	private ByteBuffer bytesOf(MemoryBlock block) throws Exception {
		byte[] bytes = new byte[(int) block.getSize()];
		block.getBytes(block.getStart(), bytes);
		return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
	}

	private Long qword(long address) {
		try {
			return pointer(memory.getLong(toAddr(address)));
		}
		catch (Exception error) {
			return null;
		}
	}

	/// The zero-terminated ASCII text at an address, or null if the bytes there are not text.
	private String text(long address, boolean identifier) {
		if (!inData(address) && !inCode(address)) {
			return null;
		}
		byte[] bytes = new byte[MAX_NAME];
		int count;
		try {
			count = memory.getBytes(toAddr(address), bytes);
		}
		catch (Exception error) {
			return null;
		}
		for (int i = 0; i < count; i++) {
			int c = bytes[i] & 0xFF;
			if (c == 0) {
				if (i == 0) {
					return null;
				}
				String value = new String(bytes, 0, i, StandardCharsets.US_ASCII);
				if (identifier && !value.matches("[A-Za-z_][A-Za-z0-9_.]*")) {
					return null;
				}
				return value;
			}
			if (c < 0x20 || c > 0x7E) {
				return null;
			}
		}
		return identifier ? null : new String(bytes, 0, count, StandardCharsets.US_ASCII);
	}

	private Function functionAt(long address) {
		Address entry = toAddr(address);
		Function function = getFunctionAt(entry);
		if (function == null) {
			CreateFunctionCmd command = new CreateFunctionCmd(entry);
			if (command.applyTo(currentProgram, monitor)) {
				function = getFunctionAt(entry);
			}
		}
		return function;
	}

	private static boolean hasDefaultName(Function function) {
		return function.getSymbol().getSource() == SourceType.DEFAULT;
	}

	// ---- RTTI ------------------------------------------------------------------------------------------------

	private int vtablesNamed = 0;
	private int virtualsNamed = 0;

	/// Find each complete object locator of x64 MSVC: signature 1, then the RVAs of the type descriptor, the class
	/// descriptor and the locator itself. Name each vtable that points to a locator, and each virtual function that
	/// only one class has.
	private int nameFromRtti() throws Exception {
		Map<Long, String> locators = new HashMap<>();
		Map<Long, Integer> locatorOffsets = new HashMap<>();
		for (MemoryBlock block : data) {
			monitor.checkCancelled();
			ByteBuffer bytes = bytesOf(block);
			long start = block.getStart().getOffset();
			for (int i = 0; i + 24 <= bytes.limit(); i += 4) {
				if (bytes.getInt(i) != 1 || Integer.toUnsignedLong(bytes.getInt(i + 20)) != start + i) {
					continue;
				}
				long type = Integer.toUnsignedLong(bytes.getInt(i + 12));
				String mangled = text(type + 16, false);
				if (mangled == null || !(mangled.startsWith(".?AV") || mangled.startsWith(".?AU"))) {
					continue;
				}
				locators.put(start + i, className(mangled));
				locatorOffsets.put(start + i, bytes.getInt(i + 4));
			}
		}
		println("RTTI: " + locators.size() + " complete object locators");

		// A vtable starts one pointer after the pointer to its locator.
		Map<Long, String> vtables = new TreeMap<>();
		for (MemoryBlock block : data) {
			monitor.checkCancelled();
			ByteBuffer bytes = bytesOf(block);
			long start = block.getStart().getOffset();
			for (int i = 0; i + 16 <= bytes.limit(); i += 8) {
				long value = pointer(bytes.getLong(i));
				String name = locators.get(value);
				if (name != null && inCode(pointer(bytes.getLong(i + 8)))) {
					int offset = locatorOffsets.get(value);
					vtables.put(start + i + 8, offset == 0 ? name : name + "@" + Integer.toHexString(offset));
				}
			}
		}

		Map<Long, List<String>> owners = new HashMap<>();
		Map<Long, String> slotNames = new HashMap<>();
		for (Map.Entry<Long, String> entry : vtables.entrySet()) {
			monitor.checkCancelled();
			String full = entry.getValue();
			String cls = full.contains("@") ? full.substring(0, full.indexOf('@')) : full;
			String label = full.contains("@") ? "vftable_" + full.substring(full.indexOf('@') + 1) : "vftable";
			Namespace space = NamespaceUtils.createNamespaceHierarchy(cls, null, currentProgram, SourceType.ANALYSIS);
			try {
				createLabel(toAddr(entry.getKey()), label, space, true, SourceType.ANALYSIS);
				vtablesNamed++;
			}
			catch (Exception error) {
				// A name that Ghidra refuses stays as it is.
			}
			for (int slot = 0;; slot++) {
				long at = entry.getKey() + 8L * slot;
				if (slot > 0 && (vtables.containsKey(at) || locators.containsKey(qword(at) == null ? 0 : qword(at)))) {
					break;
				}
				Long target = qword(at);
				if (target == null || !inCode(target)) {
					break;
				}
				owners.computeIfAbsent(target, key -> new ArrayList<>()).add(cls);
				slotNames.putIfAbsent(target, cls + "::vfunc_" + slot);
			}
		}
		for (Map.Entry<Long, List<String>> entry : owners.entrySet()) {
			if (entry.getValue().stream().distinct().count() != 1) {
				continue;
			}
			Function function = functionAt(entry.getKey());
			if (function == null || !hasDefaultName(function)) {
				continue;
			}
			String full = slotNames.get(entry.getKey());
			int split = full.lastIndexOf("::");
			Namespace space = NamespaceUtils.createNamespaceHierarchy(full.substring(0, split), null, currentProgram,
				SourceType.ANALYSIS);
			try {
				function.setParentNamespace(space);
				function.setName(full.substring(split + 2), SourceType.ANALYSIS);
				virtualsNamed++;
			}
			catch (Exception error) {
				// A name that Ghidra refuses stays as it is.
			}
		}
		return (int) locators.values().stream().distinct().count();
	}

	/// The C++ name of a type descriptor name: ".?AVBar@Foo@@" is "Foo::Bar".
	private String className(String mangled) {
		try {
			List<DemangledObject> results = DemanglerUtil.demangle(currentProgram, "??_7" + mangled.substring(4) +
				"6B@", null);
			if (results != null && !results.isEmpty()) {
				String name = results.get(0).getNamespace() != null ? results.get(0).getNamespace().getNamespaceName()
					: null;
				if (name != null && !name.isEmpty() && !name.contains(" ")) {
					return results.get(0).getNamespace().getNamespaceString().replace(" ", "_");
				}
			}
		}
		catch (Exception error) {
			// Use the plain reading below.
		}
		String body = mangled.substring(4, mangled.length() - (mangled.endsWith("@@") ? 2 : 0));
		String[] parts = body.split("@");
		StringBuilder name = new StringBuilder();
		for (int i = parts.length - 1; i >= 0; i--) {
			if (parts[i].isEmpty()) {
				continue;
			}
			if (name.length() > 0) {
				name.append("::");
			}
			name.append(parts[i]);
		}
		return name.toString().replaceAll("[^A-Za-z0-9_:]", "_");
	}

	// ---- Python method tables --------------------------------------------------------------------------------

	/// True if the 32 bytes at an index of a block are one PyMethodDef.
	private boolean isMethodDef(ByteBuffer bytes, int i) {
		if (i + METHOD_DEF_SIZE > bytes.limit()) {
			return false;
		}
		int flags = bytes.getInt(i + 16);
		if (flags == 0 || (flags & ~METHOD_FLAGS) != 0 || bytes.getInt(i + 20) != 0) {
			return false;
		}
		if (!inCode(pointer(bytes.getLong(i + 8)))) {
			return false;
		}
		long doc = pointer(bytes.getLong(i + 24));
		if (doc != 0 && !inData(doc)) {
			return false;
		}
		return text(pointer(bytes.getLong(i)), true) != null;
	}

	private static boolean isEnd(ByteBuffer bytes, int i) {
		if (i + METHOD_DEF_SIZE > bytes.limit()) {
			return true;
		}
		return bytes.getLong(i) == 0 && bytes.getLong(i + 8) == 0;
	}

	/// The name of the table: the module of a PyModuleDef, the type of a PyTypeObject, or a name from its address.
	private String tableName(long table, Map<Long, List<Long>> references) {
		for (long at : references.getOrDefault(table, List.of())) {
			String module = text(qwordOr(at - MODULE_METHODS + MODULE_NAME), true);
			if (module != null) {
				return module;
			}
			String type = text(qwordOr(at - TYPE_METHODS + TYPE_NAME), true);
			if (type != null) {
				return type;
			}
			if (qwordOr(at - 8) == SLOT_TP_METHODS) {
				return "type_spec_" + String.format("%08X", table);
			}
		}
		return "methods_" + String.format("%08X", table);
	}

	private long qwordOr(long address) {
		Long value = qword(address);
		return value == null ? 0 : value;
	}

	private int[] nameFromMethodTables() throws Exception {
		Map<Long, List<long[]>> tables = new LinkedHashMap<>();
		for (MemoryBlock block : data) {
			monitor.checkCancelled();
			ByteBuffer bytes = bytesOf(block);
			long start = block.getStart().getOffset();
			for (int i = 0; i + METHOD_DEF_SIZE <= bytes.limit(); i += 8) {
				if (!isMethodDef(bytes, i)) {
					continue;
				}
				int end = i;
				List<long[]> rows = new ArrayList<>();
				while (isMethodDef(bytes, end)) {
					rows.add(new long[] {pointer(bytes.getLong(end)), pointer(bytes.getLong(end + 8)),
						bytes.getInt(end + 16), pointer(bytes.getLong(end + 24))});
					end += METHOD_DEF_SIZE;
				}
				// A table ends with an empty entry. One entry with no end is too weak to keep.
				if (isEnd(bytes, end) && !rows.isEmpty()) {
					tables.put(start + i, rows);
				}
				i = end - 8 + METHOD_DEF_SIZE;
			}
		}

		// Find what points to each table: a PyModuleDef, a PyTypeObject or a PyType_Spec slot.
		Map<Long, List<Long>> references = new HashMap<>();
		for (MemoryBlock block : data) {
			ByteBuffer bytes = bytesOf(block);
			long start = block.getStart().getOffset();
			for (int i = 0; i + 8 <= bytes.limit(); i += 8) {
				long value = pointer(bytes.getLong(i));
				if (tables.containsKey(value)) {
					references.computeIfAbsent(value, key -> new ArrayList<>()).add(start + i);
				}
			}
		}

		int named = 0;
		for (Map.Entry<Long, List<long[]>> entry : tables.entrySet()) {
			monitor.checkCancelled();
			String table = tableName(entry.getKey(), references).replace('.', '_');
			createLabel(toAddr(entry.getKey()), "PyMethodDef_" + table, true, SourceType.ANALYSIS);
			for (long[] row : entry.getValue()) {
				String method = text(row[0], true);
				Function function = functionAt(row[1]);
				if (method == null || function == null) {
					continue;
				}
				String doc = row[3] != 0 ? text(row[3], false) : null;
				String comment = "Python: " + table + "." + method + " (flags 0x" + Long.toHexString(row[2]) + ")" +
					(doc != null ? "\n" + doc.split("\n", 2)[0] : "");
				String old = function.getComment();
				function.setComment(old == null ? comment : old.contains(comment) ? old : old + "\n" + comment);
				if (!hasDefaultName(function) && function.getSymbol().getSource() != SourceType.ANALYSIS) {
					continue;
				}
				if (!hasDefaultName(function) && function.getName().contains("$$")) {
					continue; // One C function serves two Python names: keep the first.
				}
				try {
					function.setName(table + "$$" + method, SourceType.ANALYSIS);
					named++;
				}
				catch (Exception error) {
					// A name that Ghidra refuses stays as it is.
				}
			}
		}
		return new int[] {tables.size(), named};
	}

	// ---- names.tsv -------------------------------------------------------------------------------------------

	/// Write each function that has a name that is not Ghidra's default: the RVA, the full name and the source.
	private int writeNames(Path path) throws Exception {
		int count = 0;
		Files.createDirectories(path.toAbsolutePath().getParent());
		try (BufferedWriter out = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
			out.write("rva\tname\tsource\n");
			for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
				Symbol symbol = function.getSymbol();
				if (symbol.getSource() == SourceType.DEFAULT || function.isThunk()) {
					continue;
				}
				String name = function.getName(true);
				String source = name.contains("$$") ? "python" : name.contains("::vfunc_") ? "rtti" :
					symbol.getSource().toString().toLowerCase();
				out.write(String.format("0x%08X\t%s\t%s\n", function.getEntryPoint().getOffset(), name, source));
				count++;
			}
		}
		return count;
	}
}
