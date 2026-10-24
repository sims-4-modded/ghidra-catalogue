#!/usr/bin/env python3
# ******************************************************************************
# Copyright (c) 2026 Sims 4 mods developers
# ******************************************************************************
"""Game builds for the Ghidra projects and the catalogue of The Sims 4.

A build is one module of one game version: `<module>_<version>`, for example `Simulation_x64_1.128.90.1030`.
The module is TS4_x64 (TS4_x64.exe) or Simulation_x64 (Simulation_x64.dll). The version is the text in
GameVersion.txt in the user folder. Each build has its own Ghidra project and its own catalogue tree:

  <workspace>\\ghidra\\<build>\\ts4.gpr            the Ghidra project, with build.json and names.tsv
  <workspace>\\ghidra-catalogue\\<build>\\          the catalogue tree, with build.json and fn\\
  <workspace>\\dump\\TS4_<version>\\                the decrypted image of TS4_x64.exe (TS4_x64.image.bin, image.json)

TS4_x64.exe is encrypted on disk by the activation wrapper of EA. Ghidra cannot read it. The tool imports the
decrypted image that the research build of the extender writes after the game starts. The image is a PE file in the
memory layout: the file offset of each section is its RVA. image.json holds `exe_sha256`, the SHA-256 of the
TS4_x64.exe on disk that the image came from. Simulation_x64.dll is not encrypted; the tool imports it from disk.

  ghidra_builds.py version                       print the game version
  ghidra_builds.py current [--module M]          print the build of a module of the game now
  ghidra_builds.py list                          list the builds that have a project, a tree or a dump
  ghidra_builds.py check-project <build>         exit 1, with the next step, if the build has no project
  ghidra_builds.py new --module M [--image PATH] [--dry-run]
                                                 import a module into a new project, rebase it, analyse it, name it
  ghidra_builds.py name <build>                  run the names again on a project that exists (no server may run)
  ghidra_builds.py register <build> --file PATH --imported DATE
                                                 write build.json for a project that exists
  ghidra_builds.py --self-test

The tool reads the game folder and never writes to it.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def workspace(levels: int) -> Path:
    """The folder that holds projects. TS4_WORKSPACE can give it. Else it is two folders above this repository,
    because a repository is <workspace>/projects/<repo> and a worktree is <workspace>/worktrees/<name>. levels is the
    number of folders between this file and the repository."""
    value = os.environ.get("TS4_WORKSPACE")
    if value:
        return Path(value)
    return Path(__file__).resolve().parents[levels + 2]


# The keys that the EA app writes when it installs the game. The value "Install Dir" is the game folder.
GAME_REGISTRY_KEYS = (r"SOFTWARE\Maxis\The Sims 4", r"SOFTWARE\WOW6432Node\Maxis\The Sims 4")
NO_GAME = ("The game folder is not known: the registry has no Install Dir of The Sims 4. "
           "Set TS4_GAME to the game folder.")


def game_folder() -> Path | None:
    """The game folder: TS4_GAME, else the folder that the EA app wrote in the registry, else None."""
    value = os.environ.get("TS4_GAME")
    if value:
        return Path(value)
    try:
        import winreg
    except ImportError:
        return None
    for key in GAME_REGISTRY_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as handle:
                folder, _ = winreg.QueryValueEx(handle, "Install Dir")
        except OSError:
            continue
        if folder:
            return Path(folder)
    return None


DATA = Path(os.environ.get("TS4_DATA", str(workspace(2))))
GAME = game_folder()
USER_FOLDER = Path(os.environ.get("TS4_USER", str(Path.home() / "Documents" / "Electronic Arts" / "The Sims 4")))
GHIDRA_ROOT = Path(os.environ.get("TS4_GHIDRA_ROOT", str(DATA / "ghidra")))
DUMP_ROOT = Path(os.environ.get("TS4_DUMP_ROOT", str(DATA / "dump")))
CATALOGUE = Path(os.environ.get("GHCAT_ROOT", str(DATA / "ghidra-catalogue")))
RUNS = DATA / "runs"
GHIDRA_INSTALL = Path(os.environ.get("GHIDRA_INSTALL_DIR", r"C:\tools\ghidra"))
SCRIPTS = Path(__file__).resolve().parent
PROJECT_NAME = "ts4"
MODULES = {"TS4_x64": "TS4_x64.exe", "Simulation_x64": "Simulation_x64.dll"}
ENCRYPTED = {"TS4_x64"}
IMAGE_NAME = "TS4_x64.image.bin"
TRAILER = "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
BUILD_RE = re.compile(r"(TS4_x64|Simulation_x64)_(\d+(?:\.\d+){3})")
# Code has an entropy near 6 bits for each byte. Encrypted or compressed data is near 8.
ENCRYPTED_ENTROPY = 7.5


# ---- facts about a build -------------------------------------------------------------------------------------

def read_version(path: Path) -> str:
    """Read GameVersion.txt: a length of 4 bytes, then the text (ASCII or UTF-16)."""
    raw = path.read_bytes()
    body = raw[4:] if len(raw) > 4 else raw
    for encoding in ("ascii", "utf-16-le"):
        try:
            text = body.decode(encoding).strip("\0 \r\n")
        except UnicodeDecodeError:
            continue
        m = re.search(r"\d+(?:\.\d+){3}", text)
        if m:
            return m.group(0)
    raise ValueError(f"{path} has no version")


def game_version() -> str:
    path = USER_FOLDER / "GameVersion.txt"
    try:
        return read_version(path)
    except (OSError, ValueError) as error:
        sys.exit(f"cannot read the game version from {path}: {error}")


def module_path(module: str) -> Path:
    if GAME is None:
        sys.exit(NO_GAME)
    return GAME / "Game" / "Bin" / MODULES[module]


def build_name(module: str, version: str) -> str:
    return f"{module}_{version}"


def check_build(text: str) -> tuple[str, str]:
    m = BUILD_RE.fullmatch(text)
    if not m:
        sys.exit(f"'{text}' is not a build. A build is <module>_<version>, for example Simulation_x64_1.128.90.1030; "
                 f"the module is one of {', '.join(MODULES)}")
    return m.group(1), m.group(2)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def pe_sections(path: Path) -> list[dict]:
    """Read the section table of a PE file: name, RVA, sizes, file offset and the entropy of the raw bytes."""
    with path.open("rb") as f:
        head = f.read(4096)
        if head[:2] != b"MZ":
            raise ValueError(f"{path} is not a PE file")
        pe = struct.unpack_from("<I", head, 0x3C)[0]
        f.seek(pe)
        nt = f.read(24)
        if nt[:4] != b"PE\0\0":
            raise ValueError(f"{path} is not a PE file")
        count, opt_size = struct.unpack_from("<H12xH", nt, 6)
        f.seek(pe + 24 + opt_size)
        table = f.read(40 * count)
        out = []
        for i in range(count):
            name, vsize, rva, rsize, roff = struct.unpack_from("<8sIIII", table, i * 40)
            f.seek(roff)
            sample = f.read(min(rsize, 4 << 20))
            out.append({"name": name.rstrip(b"\0").decode("ascii", "replace"), "rva": rva, "vsize": vsize,
                        "rsize": rsize, "offset": roff, "entropy": entropy(sample)})
        return out


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    return -sum(c / len(data) * math.log2(c / len(data)) for c in counts.values())


def text_entropy(path: Path) -> float:
    for s in pe_sections(path):
        if s["name"] == ".text":
            return s["entropy"]
    raise ValueError(f"{path} has no .text section")


def project_dir(build: str) -> Path:
    return GHIDRA_ROOT / build


def project_file(build: str) -> Path:
    return project_dir(build) / f"{PROJECT_NAME}.gpr"


def dump_dir(version: str) -> Path:
    return DUMP_ROOT / f"TS4_{version}"


def tree_name(build: str) -> str:
    return build


def tree_dir(build: str) -> Path:
    return CATALOGUE / tree_name(build)


def read_build_json(folder: Path) -> dict:
    try:
        return json.loads((folder / "build.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def build_info(build: str, source: Path, imported: str, module_file: Path | None) -> dict:
    module, version = check_build(build)
    disk = module_file if module_file and module_file.exists() else None
    return {
        "build": build,
        "module": module,
        "version": version,
        "program": source.name,
        "file_sha256": sha256(disk) if disk else None,
        "file_path": str(disk) if disk else None,
        "imported_sha256": sha256(source),
        "imported_from": str(source),
        "import_date": imported,
        "image": str(dump_dir(version)) if module in ENCRYPTED else None,
        "ghidra_project": str(project_file(build)),
        "names": str(project_dir(build) / "names.tsv"),
        "image_base": "0x0",
    }


def write_build_json(folder: Path, info: dict) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "build.json"
    path.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def commit_catalogue(paths: list[Path], subject: str) -> None:
    if not (CATALOGUE / ".git").exists():
        sys.exit(f"{CATALOGUE} is not a git repository; run `git init -b main` there and add the commit-msg hook")
    rels = [str(p.relative_to(CATALOGUE)).replace("\\", "/") for p in paths]
    subprocess.run(["git", "-C", str(CATALOGUE), "add", "--", *rels], check=True)
    r = subprocess.run(["git", "-C", str(CATALOGUE), "commit", "-q", "-F", "-", "--", *rels],
                       input=f"{subject}\n\n{TRAILER}\n", capture_output=True, text=True)
    if r.returncode and "nothing to commit" not in r.stdout + r.stderr:
        sys.exit(f"git commit failed in {CATALOGUE}:\n{r.stderr.strip()}")


def register(build: str, source: Path, imported: str) -> dict:
    """Write build.json in the project folder and in the catalogue tree, and commit the tree's copy."""
    module, _ = check_build(build)
    info = build_info(build, source, imported, module_path(module))
    write_build_json(project_dir(build), info)
    tree = tree_dir(build)
    (tree / "fn").mkdir(parents=True, exist_ok=True)
    keep = tree / "fn" / ".gitkeep"
    if not keep.exists():
        keep.write_text("", encoding="utf-8")
    path = write_build_json(tree, info)
    commit_catalogue([path, keep], f"Add the build file of {build}")
    return info


# ---- the source of an import ---------------------------------------------------------------------------------

def import_source(module: str, version: str, image: str | None) -> Path:
    """The file to import. Refuse the encrypted exe; check that an image comes from the exe on disk."""
    disk = module_path(module)
    if module not in ENCRYPTED:
        if image:
            sys.exit(f"{module} is not encrypted; import it from {disk}, without --image")
        if text_entropy(disk) >= ENCRYPTED_ENTROPY:
            sys.exit(f"the .text section of {disk} looks encrypted; this tool does not know this file")
        return disk
    path = Path(image) if image else dump_dir(version) / IMAGE_NAME
    if not path.exists():
        sys.exit(f"{disk.name} is encrypted on disk, and there is no decrypted image at {path}.\n"
                 "The research build of the extender writes the image after the game starts. Ask the user to\n"
                 "approve a game start with the extender, then give the image with --image.")
    meta = path.parent / "image.json"
    try:
        want = json.loads(meta.read_text(encoding="utf-8")).get("exe_sha256", "")
    except (OSError, ValueError):
        sys.exit(f"{meta} is missing or is not JSON; it must give exe_sha256 of the exe that the image came from")
    if want.lower() != sha256(disk):
        sys.exit(f"the image {path} came from another {disk.name} (SHA-256 {want}); dump the image again")
    try:
        e = text_entropy(path)
    except ValueError as error:
        sys.exit(str(error))
    if e >= ENCRYPTED_ENTROPY:
        sys.exit(f"the .text section of {path} has the entropy {e:.2f}: the image is still encrypted")
    return path


# ---- commands ------------------------------------------------------------------------------------------------

def cmd_version(_a) -> None:
    print(game_version())


def cmd_current(a) -> None:
    print(build_name(a.module, game_version()))


def cmd_list(_a) -> None:
    builds = set()
    for root in (GHIDRA_ROOT, CATALOGUE):
        if root.exists():
            builds |= {p.name for p in root.iterdir() if BUILD_RE.fullmatch(p.name)}
    version = game_version()
    print("build                                  project tree  image  now  imported")
    for b in sorted(builds):
        module, v = check_build(b)
        info = read_build_json(project_dir(b))
        image = "yes" if module in ENCRYPTED and (dump_dir(v) / IMAGE_NAME).exists() else "-  "
        print(f"{b:38} {'yes' if project_file(b).exists() else 'no ':7} {'yes' if tree_dir(b).exists() else 'no ':5} "
              f"{image:6} {'now' if v == version else '   ':4} {info.get('import_date', '')}")


def cmd_check_project(a) -> None:
    check_build(a.build)
    if not project_file(a.build).exists():
        module, _ = check_build(a.build)
        sys.exit(f"There is no Ghidra project for {a.build} ({project_file(a.build)}).\n"
                 f"Make one with: python {SCRIPTS / 'ghidra_builds.py'} new --module {module}\n"
                 "Builds with a project: " + (", ".join(sorted(p.parent.name for p in
                                                               GHIDRA_ROOT.glob(f'*/{PROJECT_NAME}.gpr'))) or "none"))
    if (project_dir(a.build) / f"{PROJECT_NAME}.lock").exists():
        print(f"warning: {project_dir(a.build)} has a lock file; a server or the GUI can have the project open",
              file=sys.stderr)


def headless(build: str, extra: list[str], log: str) -> list[str]:
    return [str(GHIDRA_INSTALL / "support" / "analyzeHeadless.bat"), str(project_dir(build)), PROJECT_NAME,
            *extra, "-scriptPath", str(SCRIPTS),
            "-log", str(RUNS / f"ghidra-{log}-{build}.log"),
            "-scriptlog", str(RUNS / f"ghidra-{log}-script-{build}.log")]


def run_headless(cmd: list[str], build: str, log: str, max_mem: str) -> None:
    RUNS.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GHIDRA_HEADLESS_MAXMEM=max_mem)
    console = RUNS / f"ghidra-{log}-console-{build}.log"
    print(f"analyzeHeadless runs now; this can take a long time. Console: {console}", flush=True)
    with console.open("w", encoding="utf-8") as out:
        r = subprocess.run(cmd, env=env, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    if r.returncode:
        sys.exit(f"analyzeHeadless failed (exit {r.returncode}); read {console}")
    text = console.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if "Ts4Prepare:" in line or "RTTI:" in line:
            print(line.strip())
    if "ERROR REPORT SCRIPT ERROR" in text or "Script error" in text:
        sys.exit(f"a script failed; read {console}")


def cmd_new(a) -> None:
    version = game_version()
    build = build_name(a.module, version)
    source = import_source(a.module, version, a.image)
    if project_file(build).exists():
        sys.exit(f"{build} has a project already: {project_file(build)}. Nothing to do.")
    names = project_dir(build) / "names.tsv"
    cmd = headless(build, ["-import", str(source),
                           "-preScript", "Ts4Prepare.java", "rebase",
                           "-postScript", "Ts4Prepare.java", "name", str(names),
                           "-max-cpu", str(a.max_cpu)], "import")
    print("command:", subprocess.list2cmdline(cmd))
    if a.dry_run:
        print(json.dumps(build_info(build, source, dt.date.today().isoformat(), module_path(a.module)), indent=2))
        return
    before = sha256(source)
    project_dir(build).mkdir(parents=True, exist_ok=True)
    started = dt.datetime.now()
    run_headless(cmd, build, "import", a.max_mem)
    if not project_file(build).exists():
        sys.exit(f"analyzeHeadless made no project at {project_file(build)}")
    info = register(build, source, dt.date.today().isoformat())
    if info["imported_sha256"] != before:
        print(f"warning: {source} changed during the import; make the project again", file=sys.stderr)
    print(f"time: {dt.datetime.now() - started}\nproject: {project_file(build)}\ntree: {tree_dir(build)}\n"
          f"serve it: tools\\ghidra\\ghidra-server.bat {build}")


def cmd_name(a) -> None:
    check_build(a.build)
    if not project_file(a.build).exists():
        sys.exit(f"no project at {project_file(a.build)}")
    program = read_build_json(project_dir(a.build)).get("program") or MODULES[check_build(a.build)[0]]
    cmd = headless(a.build, ["-process", program, "-noanalysis",
                             "-postScript", "Ts4Prepare.java", "name", str(project_dir(a.build) / "names.tsv")], "name")
    print("command:", subprocess.list2cmdline(cmd))
    run_headless(cmd, a.build, "name", a.max_mem)


def cmd_register(a) -> None:
    check_build(a.build)
    if not project_file(a.build).exists():
        sys.exit(f"no project at {project_file(a.build)}")
    print(json.dumps(register(a.build, Path(a.file), a.imported), indent=2))


# ---- self-test -----------------------------------------------------------------------------------------------

def fake_pe(path: Path, text: bytes) -> None:
    """Write a small PE file with one .text section."""
    head = bytearray(0x400)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x80)
    head[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", head, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<8sIIII", head, 0x80 + 24 + 0xF0, b".text", len(text), 0x1000, len(text), 0x400)
    path.write_bytes(bytes(head) + text)


def self_test() -> None:
    global GAME, USER_FOLDER, DUMP_ROOT
    tmp = Path(tempfile.mkdtemp(prefix="ghidra-builds-test-"))
    try:
        (tmp / "user").mkdir()
        (tmp / "user" / "GameVersion.txt").write_bytes(struct.pack("<I", 13) + b"1.128.90.1030")
        assert read_version(tmp / "user" / "GameVersion.txt") == "1.128.90.1030"
        (tmp / "v16.txt").write_bytes(struct.pack("<I", 13) + "1.2.3.4".encode("utf-16-le"))
        assert read_version(tmp / "v16.txt") == "1.2.3.4"
        assert check_build("Simulation_x64_1.128.90.1030") == ("Simulation_x64", "1.128.90.1030")
        assert BUILD_RE.fullmatch("TS4_x64_1.2") is None
        GAME, USER_FOLDER, DUMP_ROOT = tmp / "game", tmp / "user", tmp / "dump"
        (GAME / "Game" / "Bin").mkdir(parents=True)
        code = bytes(range(64)) * 64  # Few different bytes: the entropy is 6.
        noise = hashlib.sha256(b"seed").digest()
        encrypted = b"".join(hashlib.sha256(noise + bytes([i % 256, i // 256])).digest() for i in range(512))
        fake_pe(module_path("Simulation_x64"), code)
        fake_pe(module_path("TS4_x64"), encrypted)
        assert abs(text_entropy(module_path("Simulation_x64")) - 6.0) < 0.01
        assert text_entropy(module_path("TS4_x64")) > ENCRYPTED_ENTROPY
        assert import_source("Simulation_x64", "1.128.90.1030", None) == module_path("Simulation_x64")

        def refused(*args) -> str:
            try:
                import_source(*args)
            except SystemExit as stop:
                return str(stop)
            raise AssertionError(f"import_source{args} did not refuse")

        assert "no decrypted image" in refused("TS4_x64", "1.128.90.1030", None)
        image = dump_dir("1.128.90.1030") / IMAGE_NAME
        image.parent.mkdir(parents=True)
        fake_pe(image, code)
        assert "image.json" in refused("TS4_x64", "1.128.90.1030", None)
        (image.parent / "image.json").write_text(json.dumps({"exe_sha256": "00" * 32}))
        assert "another" in refused("TS4_x64", "1.128.90.1030", None)
        (image.parent / "image.json").write_text(json.dumps({"exe_sha256": sha256(module_path("TS4_x64"))}))
        assert import_source("TS4_x64", "1.128.90.1030", None) == image
        fake_pe(image, encrypted)
        assert "still encrypted" in refused("TS4_x64", "1.128.90.1030", None)
        assert "not encrypted" in refused("Simulation_x64", "1.128.90.1030", str(image))
        info = build_info("Simulation_x64_1.128.90.1030", module_path("Simulation_x64"), "2026-10-25",
                          module_path("Simulation_x64"))
        assert info["image_base"] == "0x0" and info["image"] is None and info["file_sha256"] == info["imported_sha256"]
        print("self-test passed")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    if "--self-test" in sys.argv[1:]:
        self_test()
        return
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    c = sub.add_parser("current")
    c.add_argument("--module", choices=MODULES, default="Simulation_x64")
    sub.add_parser("list")
    k = sub.add_parser("check-project")
    k.add_argument("build")
    n = sub.add_parser("new")
    n.add_argument("--module", choices=MODULES, required=True)
    n.add_argument("--image", help="the decrypted image of TS4_x64.exe (default: the image in the dump folder)")
    n.add_argument("--max-cpu", type=int, default=24)
    n.add_argument("--max-mem", default="24G")
    n.add_argument("--dry-run", action="store_true")
    m = sub.add_parser("name")
    m.add_argument("build")
    m.add_argument("--max-mem", default="16G")
    r = sub.add_parser("register")
    r.add_argument("build")
    r.add_argument("--file", required=True, help="the file that Ghidra imported")
    r.add_argument("--imported", required=True, help="the import date, YYYY-MM-DD")
    a = p.parse_args()
    {"version": cmd_version, "current": cmd_current, "list": cmd_list, "check-project": cmd_check_project,
     "new": cmd_new, "name": cmd_name, "register": cmd_register}[a.cmd](a)


if __name__ == "__main__":
    main()
