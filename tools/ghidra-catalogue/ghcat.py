#!/usr/bin/env python3
# ******************************************************************************
# Copyright (c) 2026 Sims 4 mods developers
# ******************************************************************************
"""Ghidra function catalogue of The Sims 4: look a function up once, keep it for every agent.

One Markdown file per function, keyed by RVA, in one tree for each build (one module of one game version):
`<root>/<module>_<version>/fn/<RVA>.md`, for example `Simulation_x64_1.128.90.1030/fn/0001A2B0.md`. Each file keeps
the raw disassembly, Ghidra's decompile, the callers, and the analysis agents add over time. An RVA belongs to one
build only.

  ghcat.py [--build B] get <rva|name> [--refresh] [--sections meta,asm,c,analysis,comments,callers,docs]
  ghcat.py [--build B] find <regex> [--status raw|analysed|stale] [--limit N]
  ghcat.py [--build B] note <rva> [--summary S] [--tags a,b] [--analysis-file F | --analysis S] [--comment S]
                               [--name N] [--by LANE]
  ghcat.py [--build B] sig <rva> [--by LANE]      make the shortest unique byte signature and keep it in the entry
  ghcat.py [--build B] stats
  ghcat.py build                                   the tree that the tool uses, and the build that the server serves
  ghcat.py migrate --from OLD --to NEW [--dry-run] [--by LANE]
                                                   carry the analysis of the OLD tree to the NEW tree
  ghcat.py changed --from OLD --to NEW [--class C,..] [--match RE] [--names-only] [--list-only]
                                                   list the named functions whose bodies changed between two builds
  ghcat.py --self-test

The tree: GHCAT_BINARY, else --build, else the build that the server reports, else Simulation_x64 of the game
version now. `get` prints CACHED, FETCHED or REFRESHED on its first line, then one GHCAT line (RVA, name, status,
summary, path) that memory tools can index. Only `get` (first fetch or --refresh), `note --name`, `sig` and `migrate`
call Ghidra, and only a server that serves the build of the tree.

The names of a build come from names.tsv in its Ghidra project (written by Ts4Prepare.java): the names from the
Python method tables, the RTTI, the exports, and the names that agents gave.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ghidra"))
import ghidra_builds as builds  # noqa: E402

ROOT = builds.CATALOGUE
BRIDGE = os.environ.get("GHCAT_BRIDGE", "http://127.0.0.1:8083")
SECOND_BRIDGE = os.environ.get("GHCAT_BRIDGE2", "http://127.0.0.1:8084")
FORBIDDEN_PORTS = (":8080", ":8081", ":8082")
DOC_DIRS = [Path(p) for p in os.environ.get("GHCAT_DOCS", ";".join(
    (str(builds.DATA / "projects" / "ts4_research" / "docs" / "research"), str(builds.DATA / "handovers")))).split(";")
    if p]
SECTIONS = ["Analysis", "Comments", "Disassembly", "Decompiled", "Callers", "Log"]
STATUSES = ["raw", "analysed", "stale"]
BINARY = ""  # The tree name; main() sets it.
NORMALISER_VERSION = 1


def fn_dir(binary: str | None = None) -> Path:
    return ROOT / (binary or BINARY) / "fn"


def tree_build(binary: str | None = None) -> str | None:
    name = binary or BINARY
    info = builds.read_build_json(ROOT / name)
    if info.get("build"):
        return info["build"]
    return name if builds.BUILD_RE.fullmatch(name) else None


def norm_addr(text: str) -> str | None:
    m = re.fullmatch(r"(?:0x)?([0-9a-fA-F]{1,8})", text.strip())
    return m.group(1).upper().zfill(8) if m else None


def check_url(url: str) -> str:
    if any(url.rstrip("/").endswith(p) for p in FORBIDDEN_PORTS):
        sys.exit(f"{url} is the Ghidra server of another project. The Sims 4 uses 8083 and 8084.")
    return url


def bridge(path: str, url: str | None = None, **params) -> str:
    full = f"{check_url(url or BRIDGE)}/{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(full, timeout=120) as r:
        return r.read().decode("utf-8", "replace")


def bridge_post(path: str, url: str | None = None, **params) -> str:
    data = urllib.parse.urlencode(params).encode()
    with urllib.request.urlopen(f"{check_url(url or BRIDGE)}/{path}", data=data, timeout=120) as r:
        return r.read().decode("utf-8", "replace")


# ---- the build of the server -------------------------------------------------------------------------------------

def server_build(url: str | None = None) -> dict | None:
    """The /build answer of a server: None if no server answers, {} if the server is too old to tell."""
    try:
        with urllib.request.urlopen(f"{check_url(url or BRIDGE)}/build", timeout=3) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError:
        return {}
    except (urllib.error.URLError, OSError, ValueError):
        return None


def require_server(build: str | None, url: str | None = None) -> None:
    """Stop unless the server serves the build of the tree. Never mix builds."""
    url = url or BRIDGE
    info = server_build(url)
    if info is None:
        sys.exit(f"no Ghidra server answers on {url}. Start it: tools\\ghidra\\ghidra-server.bat {build or '<build>'}")
    served = info.get("build")
    if not served or served == "unknown":
        sys.exit(f"the server on {url} does not tell its build. Stop it (curl -X POST {url}/shutdown) and start "
                 f"tools\\ghidra\\ghidra-server.bat {build or '<build>'}")
    if not build:
        sys.exit(f"the tree {BINARY} has no build.json and its name is not a build; it cannot take entries")
    if served != build:
        sys.exit(f"the server on {url} serves {served}, but the tree is {build}. Never mix builds.\n"
                 f"Use --build {served} for that server, or start tools\\ghidra\\ghidra-server.bat {build}.")
    want = builds.read_build_json(ROOT / builds.tree_name(build)).get("imported_sha256")
    have = (info.get("executable_sha256") or "").lower()
    if want and have and have not in ("null", "none") and want != have:
        sys.exit(f"the server's program (SHA-256 {have}) is not the file of {build} ({want})")


def find_bridge(build: str, urls: list[str]) -> str | None:
    for url in urls:
        info = server_build(url)
        if info and info.get("build") == build:
            return url
    return None


# ---- file format -------------------------------------------------------------------------------------------------

def parse(path: Path) -> tuple[dict, dict]:
    text = path.read_text(encoding="utf-8")
    meta, body = {}, text
    if text.startswith("---\n"):
        end = text.index("\n---\n", 4)
        for line in text[4:end].splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                meta[k.strip()] = json.loads(v) if v.startswith(("[", '"')) else v.strip()
        body = text[end + 5:]
    sections, cur = {}, None
    for line in body.splitlines():
        m = re.fullmatch(r"## (\w+)", line)
        if m and m.group(1) in SECTIONS:
            cur = m.group(1)
            sections[cur] = []
        elif cur:
            sections[cur].append(line)
    return meta, {k: "\n".join(v).strip("\n") for k, v in sections.items()}


def write(path: Path, meta: dict, sections: dict) -> None:
    out = ["---"]
    for k, v in meta.items():
        out.append(f"{k}: {json.dumps(v)}")
    out.append("---")
    for s in SECTIONS:
        out += ["", f"## {s}", sections.get(s, "").rstrip()]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    tmp.replace(path)


def subject_line(verb: str, meta: dict) -> str:
    # STE: one instruction, active voice, no full stop, at most 72 characters.
    tail = f" at 0x{meta['address']}"
    name = meta.get("name", "")
    room = 72 - len(verb) - len(tail) - 1
    if len(name) > room:
        name = name[: max(room - 3, 0)] + "..."
    return f"{verb} {name}{tail}".replace("  ", " ")


def commit(paths: Path | list[Path], subject: str, by: str) -> None:
    """Commit catalogue files. Every change goes into the history at once."""
    root = ROOT
    if not (root / ".git").exists():
        sys.exit(f"{root} is not a git repository; run `git init -b main` there first")
    rels = [str(p.relative_to(root)).replace("\\", "/") for p in ([paths] if isinstance(paths, Path) else paths)]
    body = f"Lane: {by}." if by else ""
    msg = subject + ("\n\n" + body if body else "") + "\n\n"
    for attempt in range(20):
        add = subprocess.run(["git", "-C", str(root), "add", "--", *rels], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL)
        if add.returncode == 0:
            r = subprocess.run(["git", "-C", str(root), "commit", "-q", "-F", "-", "--", *rels], input=msg,
                               capture_output=True, text=True)
            if r.returncode == 0:
                return
            if "nothing to commit" in (r.stdout + r.stderr) or "no changes added" in (r.stdout + r.stderr):
                return
            err = r.stderr
        else:
            err = add.stderr
        if "index.lock" not in err:
            sys.exit(f"git commit failed for {', '.join(rels[:3])}:\n{err.strip()}")
        time.sleep(0.5 + attempt * 0.25)  # another agent commits now; wait and try again
    sys.exit("git commit failed: the index stayed locked")


def ghcat_line(meta: dict, path: Path) -> str:
    return (f"GHCAT {meta.get('binary', BINARY)} 0x{meta['address']} {meta.get('name', '?')} "
            f"[{meta.get('status', 'raw')}] {meta.get('summary', '') or '(no summary yet)'} -> {path}")


# ---- fetch -------------------------------------------------------------------------------------------------------

def resolve(query: str) -> str:
    if not query.strip():
        sys.exit("give an RVA or a name")
    addr = norm_addr(query)
    if addr and not re.fullmatch(r"[A-Za-z_]\w*", query):
        return addr
    if addr and query.lower().startswith("0x"):
        return addr
    # A name: look in the catalogue first, then in names.tsv, then ask Ghidra.
    for p in fn_dir().glob("*.md"):
        meta, _ = parse(p)
        if query in (meta.get("name"), meta.get("short_name")):
            return meta["address"]
    build = tree_build()
    if build:
        names = Names.load(build, missing_ok=True)
        hits = names.by_name.get(query, []) or [r for n, rs in names.by_name.items() if n.split("::")[-1] == query
                                                 for r in rs]
        if len(hits) == 1:
            return f"{hits[0]:08X}"
    if addr:
        return addr
    require_server(build)
    hits = [l for l in bridge("searchFunctions", query=query, limit=50).splitlines() if " @ " in l]
    exact = [l for l in hits if l.split(" @ ")[0].strip() == query.split("::")[-1]]
    pick = exact or hits
    if len(pick) != 1:
        sys.exit(f"name '{query}' gives {len(pick)} matches; pass an RVA:\n" + "\n".join(pick[:20]))
    return pick[0].split(" @ ")[1].strip().upper().zfill(8)


def fetch(addr: str, url: str | None = None) -> tuple[dict, dict]:
    info = bridge("get_function_by_address", url, address=f"0x{addr}")
    if "Function:" not in info:
        sys.exit(f"Ghidra has no function at 0x{addr}: {info.strip()[:200]}")
    decomp = bridge("decompile_function", url, address=f"0x{addr}")
    disasm = bridge("disassemble_function", url, address=f"0x{addr}")
    callers = bridge("xrefs_to", url, address=f"0x{addr}", limit=200)
    short = re.search(r"Function: (\S+)", info).group(1)
    sig = (re.search(r"Signature: (.+)", info) or [None, ""])[1].strip()
    body = re.search(r"Body: ([0-9a-fA-F]+) - ([0-9a-fA-F]+)", info)
    entry = int((re.search(r"Entry: ([0-9a-fA-F]+)", info) or [None, addr])[1], 16)
    build = tree_build() or ""
    full = Names.load(build, missing_ok=True).by_rva.get(entry, [short])[0] if build else short
    meta = {
        "address": addr,
        "binary": BINARY,
        "build": build,
        "name": full if full.split("::")[-1] == short else short,
        "short_name": short,
        "signature": sig,
        "size": hex(int(body.group(2), 16) - int(body.group(1), 16) + 1) if body else "",
        "fetched": dt.date.today().isoformat(),
        "status": "raw",
        "summary": "",
        "tags": [],
    }
    sections = {
        "Analysis": "",
        "Comments": "",
        "Disassembly": "```asm\n" + disasm.strip() + "\n```",
        "Decompiled": "```c\n" + decomp.strip() + "\n```",
        "Callers": "```\n" + callers.strip() + "\n```",
        "Log": f"- {meta['fetched']} fetched from Ghidra",
    }
    return meta, sections


def doc_mentions(addr: str, limit: int = 15) -> list[str]:
    short = addr.lstrip("0") or "0"
    rx = re.compile(rf"0x0*{short}\b", re.I)
    out = []
    for d in DOC_DIRS:
        if not d.exists():
            continue
        for p in d.rglob("*.md"):
            try:
                if rx.search(p.read_text(encoding="utf-8", errors="replace")):
                    out.append(str(p))
            except OSError:
                pass
            if len(out) >= limit:
                return out
    return out


# ---- the names of a build and the matcher ------------------------------------------------------------------------

class Names:
    """The named functions of one build, from names.tsv: each name and the RVA of its body."""

    def __init__(self, rows: list[tuple[int, str]]):
        self.by_rva: dict[int, list[str]] = collections.defaultdict(list)
        self.by_name: dict[str, list[int]] = collections.defaultdict(list)
        for rva, name in rows:
            self.by_rva[rva].append(name)
            self.by_name[name].append(rva)

    @classmethod
    def load(cls, build: str, missing_ok: bool = False) -> "Names":
        path = builds.project_dir(build) / "names.tsv"
        if not path.exists():
            if missing_ok:
                return cls([])
            sys.exit(f"there is no names.tsv for {build} ({path}); run: python tools/ghidra/ghidra_builds.py name "
                     f"{build}")
        rows = []
        with path.open(encoding="utf-8") as f:
            next(f, None)
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2 and parts[0]:
                    rows.append((int(parts[0], 16), parts[1]))
        return cls(rows)

    def names(self) -> dict[int, str]:
        """One stable name for each body, for the normaliser: the smallest name at the address."""
        return {rva: min(v) for rva, v in self.by_rva.items()}


def match_name(old: Names, new: Names, name: str, old_rva: int) -> tuple[int | None, str]:
    """Find the body of one named function in the new build, by its name, never by its RVA.

    Returns the new RVA (or None if the name is gone) and a note: "" or "ambiguous".
    """
    olds, news = old.by_name.get(name, []), new.by_name.get(name, [])
    if not news:
        return None, ""
    if len(news) == 1:
        return news[0], ""
    if len(olds) == len(news) and old_rva in olds:
        return news[olds.index(old_rva)], ""  # The same names in the same order.
    return news[0], "ambiguous"


# ---- the body normaliser -----------------------------------------------------------------------------------------

LINE_RE = re.compile(r"^\s*([0-9a-fA-F]{6,16}):\s+(.*)$")
HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")
# Numbers in this range are RVAs in a module of the game. Smaller numbers are field offsets and constants.
ADDRESS_LOW, ADDRESS_HIGH = 0x10000, 0x10000000


def disasm_lines(text: str) -> list[tuple[int, str]]:
    out = []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if m:
            out.append((int(m.group(1), 16), m.group(2).split(" ; ", 1)[0].strip()))
    return out


def normalise(lines: list[tuple[int, str]], start: int, end: int, names: dict[int, str]) -> tuple[list[str], list[str]]:
    """Make the instructions independent of where the linker put the code.

    A jump inside the body becomes an offset from the start; a call or a reference to a named function becomes its
    name; any other address becomes ADDR. Small numbers (field offsets, constants) stay. Returns the normalised
    lines and the call targets.
    """
    out, calls = [], []
    for _addr, text in lines:
        mnemonic, _, operands = text.partition(" ")
        mnemonic = mnemonic.upper()
        branch = mnemonic == "CALL" or mnemonic.startswith("J") or mnemonic.startswith("LOOP")

        def token(m: re.Match) -> str:
            v = int(m.group(1), 16)
            if start <= v < end:
                return f"L+{v - start:x}"
            if v in names:
                return f"<{names[v]}>"
            if branch or ADDRESS_LOW <= v < ADDRESS_HIGH:
                return "ADDR"
            return m.group(0).lower()

        ops = HEX_RE.sub(token, operands.strip())
        out.append(f"{mnemonic} {ops}".strip())
        if mnemonic == "CALL":
            calls.append(ops)
    return out, calls


def digest(disasm_text: str, size: int | None, names: dict[int, str]) -> dict | None:
    lines = disasm_lines(disasm_text)
    if not lines:
        return None
    start = lines[0][0]
    if not size:
        size = lines[-1][0] - start + 1
    norm, calls = normalise(lines, start, start + size, names)
    return {"hash": hashlib.sha256("\n".join(norm).encode()).hexdigest()[:16], "size": size, "insns": len(norm),
            "calls": calls, "v": NORMALISER_VERSION}


def describe_change(old: dict, new: dict) -> str:
    parts = []
    if old["size"] != new["size"]:
        parts.append(f"size {old['size']:#x}->{new['size']:#x}")
    if old["insns"] != new["insns"]:
        parts.append(f"instructions {old['insns']}->{new['insns']}")
    a, b = collections.Counter(old["calls"]), collections.Counter(new["calls"])
    gone, added = sorted((a - b).elements()), sorted((b - a).elements())
    if added:
        parts.append("new calls " + ", ".join(dict.fromkeys(added)))
    if gone:
        parts.append("calls gone " + ", ".join(dict.fromkeys(gone)))
    return "; ".join(parts) or "same size and calls, other instructions changed"


def section_code(text: str) -> str:
    return re.sub(r"^```\w*\n|\n```$", "", text.strip())


def size_of(meta: dict) -> int | None:
    try:
        return int(meta.get("size", ""), 16)
    except (TypeError, ValueError):
        return None


class BodyCache:
    """The digests of one build, kept beside its Ghidra project, so that `changed` asks Ghidra once."""

    def __init__(self, build: str):
        self.path = builds.project_dir(build) / "bodies.jsonl"
        self.data: dict[int, dict] = {}
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                if row.get("v") == NORMALISER_VERSION:
                    self.data[row["rva"]] = row
        except (OSError, ValueError):
            pass

    def put(self, rva: int, d: dict) -> None:
        self.data[rva] = dict(d, rva=rva)
        if self.path.parent.exists():
            with self.path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(self.data[rva]) + "\n")


def body_from_bridge(url: str, rva: int, names: dict[int, str]) -> dict | None:
    info = bridge("get_function_by_address", url, address=f"0x{rva:08X}")
    body = re.search(r"Body: ([0-9a-fA-F]+) - ([0-9a-fA-F]+)", info)
    entry = re.search(r"Entry: ([0-9a-fA-F]+)", info)
    if not body or not entry or int(entry.group(1), 16) != rva:
        return None
    size = int(body.group(2), 16) - int(body.group(1), 16) + 1
    return digest(bridge("disassemble_function", url, address=f"0x{rva:08X}"), size, names)


def find_signature(pattern: str, url: str | None = None) -> list[int]:
    lines = bridge("find_bytes", url, pattern=pattern, limit=5).splitlines()
    return [int(l.split()[0], 16) for l in lines if l.strip()]


# ---- commands ----------------------------------------------------------------------------------------------------

def cmd_get(a) -> None:
    addr = resolve(a.target)
    path = fn_dir() / f"{addr}.md"
    state = "CACHED"
    if a.refresh or not path.exists():
        require_server(tree_build())
        meta, sections = fetch(addr)
        if path.exists():  # keep what agents wrote; replace only Ghidra's parts
            old_meta, old = parse(path)
            for k in ("summary", "tags", "status", "carried_from", "carried_from_address", "byte_signature"):
                if k in old_meta:
                    meta[k] = old_meta[k]
            for s in ("Analysis", "Comments"):
                sections[s] = old.get(s, "")
            sections["Log"] = (old.get("Log", "") + f"\n- {meta['fetched']} refreshed from Ghidra").strip()
            state = "REFRESHED"
        else:
            state = "FETCHED"
        write(path, meta, sections)
        verb = "Replace the Ghidra parts of" if state == "REFRESHED" else "Add"
        commit(path, subject_line(verb, meta), a.by or "")
    meta, sections = parse(path)
    print(f"{state} {path}")
    print(ghcat_line(meta, path))
    want = a.sections.split(",")
    if "meta" in want:
        print(f"build: {meta.get('build', '?')}  signature: {meta.get('signature', '')}\n"
              f"size: {meta.get('size', '')}  fetched: {meta.get('fetched', '')}"
              f"  tags: {', '.join(meta.get('tags', []) or [])}"
              + (f"\nbyte signature: {meta['byte_signature']}" if meta.get("byte_signature") else "")
              + (f"\ncarried from {meta['carried_from']} at 0x{meta.get('carried_from_address', '?')}"
                 if meta.get("carried_from") else ""))
    for key, name in (("analysis", "Analysis"), ("comments", "Comments"), ("callers", "Callers"),
                      ("asm", "Disassembly"), ("c", "Decompiled")):
        if key in want and sections.get(name):
            lines = sections[name].splitlines()
            print(f"\n## {name}")
            print("\n".join(lines[:a.max_lines]))
            if len(lines) > a.max_lines:
                print(f"... {len(lines) - a.max_lines} more lines in {path}")
    if "docs" in want:
        docs = doc_mentions(addr)
        if docs:
            print("\n## Mentioned in notes\n" + "\n".join(docs))


def cmd_find(a) -> None:
    rx = re.compile(a.pattern, re.I)
    n = 0
    for p in sorted(fn_dir().glob("*.md")):
        meta, sections = parse(p)
        if a.status and meta.get("status") != a.status:
            continue
        hay = " ".join([meta.get("name", ""), meta.get("summary", ""), " ".join(meta.get("tags", []) or []),
                        sections.get("Analysis", ""), sections.get("Comments", "")])
        if rx.search(hay) or rx.search(meta["address"]):
            print(ghcat_line(meta, p))
            n += 1
            if n >= a.limit:
                break
    if not n:
        print(f"no catalogue entry in {BINARY} matches; use `get` on an RVA or name to fetch one")


def cmd_note(a) -> None:
    addr = norm_addr(a.address) or sys.exit("note needs an RVA")
    path = fn_dir() / f"{addr}.md"
    if not path.exists():
        sys.exit(f"no entry for 0x{addr} in {BINARY}; run `get` first")
    meta, sections = parse(path)
    today = dt.date.today().isoformat()
    by = a.by or "agent"
    changed = []
    if a.name:
        require_server(tree_build())
        answer = bridge_post("rename_function_by_address", function_address=f"0x{addr}", new_name=a.name)
        if "renamed" not in answer.lower():
            sys.exit(f"Ghidra did not rename 0x{addr}: {answer.strip()[:200]}")
        meta["name"] = meta["short_name"] = a.name
        changed.append("name")
    if a.summary:
        meta["summary"] = a.summary
        changed.append("summary")
    if a.tags:
        meta["tags"] = sorted(set((meta.get("tags") or []) + [t.strip() for t in a.tags.split(",") if t.strip()]))
        changed.append("tags")
    text = Path(a.analysis_file).read_text(encoding="utf-8") if a.analysis_file else a.analysis
    if text:
        sections["Analysis"] = (sections.get("Analysis", "") + f"\n\n### {today} ({by})\n" + text.strip()).strip()
        meta["status"] = "analysed"
        changed.append("analysis")
    if a.comment:
        sections["Comments"] = (sections.get("Comments", "") + f"\n- {today} ({by}): {a.comment.strip()}").strip()
        changed.append("comment")
    if not changed:
        sys.exit("nothing to add")
    sections["Log"] = (sections.get("Log", "") + f"\n- {today} {by}: {', '.join(changed)}").strip()
    write(path, meta, sections)
    verb = ("Add analysis of" if "analysis" in changed else "Give a name to" if "name" in changed
            else "Change the summary of" if "summary" in changed
            else "Add a comment to" if "comment" in changed else "Change the tags of")
    commit(path, subject_line(verb, meta), by)
    print(ghcat_line(meta, path))


def cmd_sig(a) -> None:
    addr = norm_addr(a.address) or sys.exit("sig needs an RVA")
    path = fn_dir() / f"{addr}.md"
    if not path.exists():
        sys.exit(f"no entry for 0x{addr} in {BINARY}; run `get` first")
    require_server(tree_build())
    answer = bridge("signature", address=f"0x{addr}").strip()
    m = re.fullmatch(r"(unique|not unique) (\d+) (.+)", answer)
    if not m:
        sys.exit(f"Ghidra made no signature for 0x{addr}: {answer[:200]}")
    if m.group(1) != "unique":
        sys.exit(f"no unique signature in the first {m.group(2)} bytes of 0x{addr}: {m.group(3)}\n"
                 "Use a signature of a caller, or of a unique instruction inside the function, in its place.")
    meta, sections = parse(path)
    meta["byte_signature"] = m.group(3)
    today = dt.date.today().isoformat()
    by = a.by or "agent"
    sections["Comments"] = (sections.get("Comments", "") +
                            f"\n- {today} ({by}): the byte signature is `{m.group(3)}` ({m.group(2)} bytes)").strip()
    sections["Log"] = (sections.get("Log", "") + f"\n- {today} {by}: byte signature").strip()
    write(path, meta, sections)
    commit(path, subject_line("Add the byte signature of", meta), by)
    print(f"SIG 0x{addr} {m.group(3)}")


def cmd_stats(_a) -> None:
    files = list(fn_dir().glob("*.md"))
    counts = collections.Counter(parse(p)[0].get("status", "raw") for p in files)
    print(f"{BINARY}: {len(files)} functions, " + ", ".join(f"{counts.get(s, 0)} {s}" for s in STATUSES)
          + f"  ({fn_dir()})")


def cmd_build(_a) -> None:
    info = server_build()
    print(f"tree: {BINARY} (build {tree_build() or '?'}) -> {ROOT / BINARY}")
    if info is None:
        print(f"server: none on {BRIDGE}")
    else:
        print(f"server: {BRIDGE} serves {info.get('build', '(it does not tell)')}")
    print(f"game: version {builds.game_version()}")


def cmd_migrate(a) -> None:
    builds.check_build(a.old)
    builds.check_build(a.new)
    old_tree, new_tree = builds.tree_name(a.old), builds.tree_name(a.new)
    if not (ROOT / old_tree / "fn").exists():
        sys.exit(f"no tree {ROOT / old_tree}")
    if not (ROOT / new_tree / "build.json").exists():
        sys.exit(f"no tree {ROOT / new_tree} with a build.json; make the build first: "
                 f"python tools/ghidra/ghidra_builds.py new --module {builds.check_build(a.new)[0]}")
    global BINARY
    BINARY = new_tree
    require_server(a.new)
    old, new = Names.load(a.old), Names.load(a.new)
    old_names, new_names = old.names(), new.names()
    today = dt.date.today().isoformat()
    by = a.by or "migrate"
    report = collections.defaultdict(list)
    written: list[Path] = []
    for p in sorted((ROOT / old_tree / "fn").glob("*.md")):
        meta, sections = parse(p)
        old_rva = int(meta["address"], 16)
        label = meta.get("name", meta["address"])
        new_rva, note = None, ""
        names = old.by_rva.get(old_rva, [])
        if names:
            new_rva, note = match_name(old, new, names[0], old_rva)
            if new_rva is None:
                report["removed"].append(f"{label} (0x{meta['address']})")
                continue
        elif meta.get("byte_signature"):
            # A function with no name: find its byte signature in the new build.
            hits = find_signature(meta["byte_signature"])
            if len(hits) == 1:
                new_rva, note = hits[0], "found by its byte signature"
            else:
                report["signature not unique"].append(f"{label} (0x{meta['address']}): {len(hits)} hits")
                continue
        if new_rva is None:
            report["not matched (no name and no byte signature)"].append(f"{label} (0x{meta['address']})")
            continue
        addr = f"{new_rva:08X}"
        target = ROOT / new_tree / "fn" / f"{addr}.md"
        if target.exists() and parse(target)[0].get("carried_from") == a.old:
            report["carried before"].append(f"{label} -> 0x{addr}")
            continue
        if target.exists():
            new_meta, new_sections = parse(target)
        else:
            new_meta, new_sections = fetch(addr)
        before = digest(section_code(sections.get("Disassembly", "")), size_of(meta), old_names)
        after = digest(section_code(new_sections.get("Disassembly", "")), size_of(new_meta), new_names)
        same = before is not None and after is not None and before["hash"] == after["hash"]
        change = "" if same else (describe_change(before, after) if before and after else "no disassembly to compare")
        has_work = bool(sections.get("Analysis") or sections.get("Comments") or meta.get("summary"))
        status = meta.get("status", "raw") if same else ("stale" if has_work else "raw")
        for k in ("summary", "tags"):
            if meta.get(k) and not new_meta.get(k):
                new_meta[k] = meta[k]
        if not target.exists() or new_meta.get("status", "raw") == "raw":
            new_meta["status"] = status  # Keep the status of an entry that an agent analysed in the new build.
        new_meta["carried_from"] = a.old
        new_meta["carried_from_address"] = meta["address"]
        line = (f"- {today} ({by}): carried from {a.old} at 0x{meta['address']}; "
                + ("the body did not change" if same else f"the body changed: {change}")
                + (f" ({note})" if note else ""))
        for s in ("Analysis", "Comments"):
            if sections.get(s):
                carried = f"### Carried from {a.old}\n{sections[s]}" if s == "Analysis" else sections[s]
                new_sections[s] = (new_sections.get(s, "") + "\n\n" + carried).strip()
        new_sections["Comments"] = (new_sections.get("Comments", "") + "\n" + line).strip()
        new_sections["Log"] = (new_sections.get("Log", "") + f"\n- {today} {by}: carried from {a.old}").strip()
        key = "carried unchanged" if same else "carried changed (stale)"
        report[key].append(f"{label} 0x{meta['address']} -> 0x{addr}" + ("" if same else f": {change}")
                           + (f" ({note})" if note else ""))
        if not a.dry_run:
            write(target, new_meta, new_sections)
            written.append(target)
    if written:
        commit(written, f"Carry the analysis from {a.old} to {a.new}"[:72], by)
    print(f"MIGRATE {a.old} -> {a.new}{' (dry run, nothing written)' if a.dry_run else ''}")
    for key in ("carried unchanged", "carried changed (stale)", "removed", "signature not unique",
                "not matched (no name and no byte signature)", "carried before"):
        items = report.get(key, [])
        print(f"  {key}: {len(items)}")
        if key != "carried unchanged" or a.verbose:
            for item in items:
                print(f"    {item}")


def name_filter(a):
    classes = {c.strip() for c in (a.cls or "").split(",") if c.strip()}
    rx = re.compile(a.match) if a.match else None

    def keep(name: str) -> bool:
        owner = re.split(r"\$\$|::(?=[^:]*$)", name, maxsplit=1)[0] if ("$$" in name or "::" in name) else ""
        if classes and not any(owner == c or owner.endswith("::" + c) for c in classes):
            return False
        return not rx or bool(rx.search(name))
    return keep


def cmd_changed(a) -> None:
    builds.check_build(a.old)
    builds.check_build(a.new)
    old, new = Names.load(a.old), Names.load(a.new)
    keep = name_filter(a)
    keys = sorted({k for k in list(old.by_name) + list(new.by_name) if keep(k)})
    rows = []  # (state, name, old rva, new rva, note)
    for name in keys:
        olds = old.by_name.get(name, [])
        if not olds:
            rows.append(("added", name, None, new.by_name[name][0], ""))
            continue
        for old_rva in olds:
            new_rva, note = match_name(old, new, name, old_rva)
            rows.append(("removed" if new_rva is None else "pair", name, old_rva, new_rva, note))
    if a.list_only:
        for state, name, o, n, note in rows:
            if state != "pair" or note:
                print(f"{state if state != 'pair' else note:10} {name}")
        return
    caches, urls, sources = {}, {}, {}
    for build, explicit in ((a.old, a.from_bridge), (a.new, a.to_bridge)):
        caches[build] = BodyCache(build)
        urls[build] = find_bridge(build, [explicit] if explicit else [BRIDGE, SECOND_BRIDGE])
        sources[build] = {int(parse(p)[0]["address"], 16): p for p in (ROOT / builds.tree_name(build) / "fn").glob("*.md")}
    names = {a.old: old.names(), a.new: new.names()}

    def body(build: str, rva: int) -> dict | None:
        cache = caches[build]
        if rva in cache.data:
            return cache.data[rva]
        d = None
        if rva in sources[build]:
            meta, sections = parse(sources[build][rva])
            d = digest(section_code(sections.get("Disassembly", "")), size_of(meta), names[build])
        elif urls[build]:
            d = body_from_bridge(urls[build], rva, names[build])
        if d:
            cache.put(rva, d)
        return d

    counts = collections.Counter()
    missing = set()
    for state, name, o, n, note in rows:
        if state != "pair":
            counts[state] += 1
            if not a.names_only:
                print(f"{state:9} {name}")
            continue
        before, after = body(a.old, o), body(a.new, n)
        if before is None or after is None:
            counts["unknown"] += 1
            missing |= {b for b, d in ((a.old, before), (a.new, after)) if d is None}
            continue
        if before["hash"] == after["hash"] and not note:
            counts["unchanged"] += 1
            continue
        counts["changed"] += 1
        if a.names_only:
            print(name)
        else:
            print(f"changed   {name}  0x{o:08X} -> 0x{n:08X}: "
                  f"{describe_change(before, after) if before['hash'] != after['hash'] else 'same body'}"
                  + (f" ({note})" if note else ""))
    print(f"CHANGED {a.old} -> {a.new}: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())), file=sys.stderr)
    for build in sorted(missing):
        print(f"no body source for {build}: start tools\\ghidra\\ghidra-server.bat {build} 8084 "
              f"(or 8083), then run this again", file=sys.stderr)


# ---- self-test ---------------------------------------------------------------------------------------------------

def self_test() -> None:
    """Test the matcher, the normaliser and the filters on small fake builds. The test needs no Ghidra and no game."""
    old = Names([(0x1000, "sims4$$update"), (0x1100, "Zone::vfunc_3"), (0x1200, "sims4$$gone"),
                 (0x1400, "Twice::vfunc_1"), (0x1500, "Twice::vfunc_1")])
    new = Names([(0x2000, "sims4$$update"), (0x2100, "Zone::vfunc_3"), (0x2400, "Twice::vfunc_1"),
                 (0x2500, "Twice::vfunc_1"), (0x2600, "sims4$$renamed")])
    assert match_name(old, new, "sims4$$update", 0x1000) == (0x2000, "")
    assert match_name(old, new, "sims4$$gone", 0x1200) == (None, "")
    assert match_name(old, new, "Twice::vfunc_1", 0x1500) == (0x2500, "")

    def body(base: int, call: int, extra: str = "") -> str:
        return "\n".join([
            f"{base:08x}: PUSH RBX",
            f"{base + 1:08x}: CMP byte ptr [0x{0x450279a + base:x}],0x0",
            f"{base + 8:08x}: JNZ 0x{base + 0x20:08x}",
            f"{base + 10:08x}: MOV EAX,dword ptr [RBX + 0x48c]",
            f"{base + 16:08x}: CALL 0x{call:08x} ; a comment",
            f"{base + 21:08x}: CALL 0x004c97e0",
            extra,
            f"{base + 0x20:08x}: RET"]).replace("\n\n", "\n")

    on, nn = old.names(), new.names()
    a = digest(body(0x1000, 0x1100), 0x30, on)
    b = digest(body(0x2000, 0x2100), 0x30, nn)
    assert a["hash"] == b["hash"], "moved code must not count as a change"
    assert a["calls"] == ["<Zone::vfunc_3>", "ADDR"], a["calls"]
    c = digest(body(0x2000, 0x2600, f"{0x2000 + 26:08x}: MOVSS XMM0,dword ptr [0x3f800000]"), 0x34, nn)
    assert c["hash"] != a["hash"]
    text = describe_change(a, c)
    assert "size 0x30->0x34" in text and "instructions 7->8" in text, text
    assert "new calls <sims4$$renamed>" in text and "calls gone <Zone::vfunc_3>" in text, text
    d = digest(body(0x2000, 0x2100).replace("0x48c", "0x490"), 0x30, nn)
    assert d["hash"] != a["hash"], "a new field offset is a change"
    flt = name_filter(argparse.Namespace(cls="Zone", match=None))
    assert flt("Zone::vfunc_3") and flt("game::Zone::vfunc_1") and not flt("ZoneX::vfunc_3")
    flt = name_filter(argparse.Namespace(cls="sims4", match="upd"))
    assert flt("sims4$$update") and not flt("sims4$$gone") and not flt("other$$update")
    assert norm_addr("1a2b") == "00001A2B" and norm_addr("0x0001A2B0") == "0001A2B0" and norm_addr("zz") is None
    for port in FORBIDDEN_PORTS:
        try:
            check_url("http://127.0.0.1" + port)
        except SystemExit:
            continue
        raise AssertionError(f"the port {port} of another project must be refused")
    print("self-test passed")


def main() -> None:
    global BINARY
    if "--self-test" in sys.argv[1:]:
        self_test()
        return
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--build", help="the build of the tree to use, <module>_<version>")
    p.add_argument("--self-test", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("get")
    g.add_argument("target")
    g.add_argument("--refresh", action="store_true")
    g.add_argument("--sections", default="meta,analysis,comments,c,docs")
    g.add_argument("--max-lines", type=int, default=300)
    g.add_argument("--by", help="lane name for the commit")
    f = sub.add_parser("find")
    f.add_argument("pattern")
    f.add_argument("--status", choices=STATUSES)
    f.add_argument("--limit", type=int, default=50)
    n = sub.add_parser("note")
    n.add_argument("address")
    n.add_argument("--summary")
    n.add_argument("--tags")
    n.add_argument("--analysis")
    n.add_argument("--analysis-file")
    n.add_argument("--comment")
    n.add_argument("--name", help="give the function this name in Ghidra and in the entry")
    n.add_argument("--by")
    s = sub.add_parser("sig")
    s.add_argument("address")
    s.add_argument("--by")
    sub.add_parser("stats")
    sub.add_parser("build")
    m = sub.add_parser("migrate")
    m.add_argument("--from", dest="old", required=True)
    m.add_argument("--to", dest="new", required=True)
    m.add_argument("--dry-run", action="store_true")
    m.add_argument("--verbose", action="store_true", help="list the unchanged entries too")
    m.add_argument("--by")
    c = sub.add_parser("changed")
    c.add_argument("--from", dest="old", required=True)
    c.add_argument("--to", dest="new", required=True)
    c.add_argument("--class", dest="cls", help="comma-separated owners: a C++ class or a Python module or type")
    c.add_argument("--match", help="regex on the full function name")
    c.add_argument("--names-only", action="store_true", help="print only the names of changed functions")
    c.add_argument("--list-only", action="store_true", help="compare names.tsv only: added and removed names")
    c.add_argument("--from-bridge", help="the server of the old build (default: probe 8083 and 8084)")
    c.add_argument("--to-bridge", help="the server of the new build (default: probe 8083 and 8084)")
    a = p.parse_args()
    if os.environ.get("GHCAT_BINARY"):
        BINARY = os.environ["GHCAT_BINARY"]
    elif a.build:
        builds.check_build(a.build)
        BINARY = builds.tree_name(a.build)
    elif a.cmd not in ("migrate", "changed"):
        served = server_build()
        build = served.get("build") if served else None
        BINARY = builds.tree_name(build if build and builds.BUILD_RE.fullmatch(build) else
                                  builds.build_name("Simulation_x64", builds.game_version()))
    {"get": cmd_get, "find": cmd_find, "note": cmd_note, "sig": cmd_sig, "stats": cmd_stats, "build": cmd_build,
     "migrate": cmd_migrate, "changed": cmd_changed}[a.cmd](a)


if __name__ == "__main__":
    main()
