#!/usr/bin/env python3
# ******************************************************************************
# Copyright (c) 2026 Sims 4 mods developers
# ******************************************************************************
"""Record the hashes of each version of The Sims 4 in a local git repository, and find when EA changed the game.

EA updates the game often through the EA app, and a new pack also changes it. This tool keeps a manifest of the game
folder in <workspace>\\game-builds: the game version (GameVersion.txt), the installed packs, and the SHA-256, size,
time and PE version of each game file. It writes no file in the game folder and copies no game data: only hashes and
metadata go into git. The DLL of the mod loader and its mods folder are ours, not game files, and go in a separate
file (ea/ours.json).

The tool hashes each exe, DLL and .pyd, each zip of the game Python, each small file, and each file below
--hash-limit. A large package gets its size and time only, unless --rehash.

    python tools/game_builds.py record [--rehash]
    python tools/game_builds.py check [--quick]
    python tools/game_builds.py diff <rev-a> [<rev-b>]        (a commit or a tag, for example ts4-1.128.90.1030)
    python tools/game_builds.py --self-test

check exits with 1 when the version or a hashed file changed since the last record, 2 when only the list of packs
changed, and 0 when the game is as recorded. Skill: ts4-game-builds.
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

USER_FOLDER = Path(os.environ.get("TS4_USER", str(Path.home() / "Documents" / "Electronic Arts" / "The Sims 4")))
# The names that the DLL of the mod loader can have in Game\Bin, and the text that marks our build of it.
OURS = {"Game/Bin/version.dll", "Game/Bin/winmm.dll", "Game/Bin/dinput8.dll", "Game/Bin/dxgi.dll"}
OURS_FOLDERS = ("Game/Bin/mods/",)
LOADER_MARKER = b"Ts4ModLoaderVersion"
PACK_RE = re.compile(r"(EP|GP|SP|FP)\d+")
TRAILER = "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
CHUNK = 8 * 1024 * 1024
MAX_RSRC = 32 * 1024 * 1024
HASH_LIMIT = 16 * 1024 * 1024
LIST_LIMIT = 8
BODY_LIMIT = 40


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


GAME = game_folder()
TRACKING_REPO = workspace(1) / "game-builds"
HASH_CACHE = workspace(1) / "cache" / "game-builds-hash-cache.json"


def say(text: str) -> None:
    print(text, flush=True)


# ---------------------------------------------------------------------------------------------------------------
# Read the game files. Every open is read only. Python opens files on Windows with share read and share write, so
# a game that runs does not see a lock.


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


class HashCache:
    """Keep the SHA-256 of each file by (path, size, mtime), so that a second run reads no unchanged file."""

    def __init__(self, path: Path | None, rehash: bool = False):
        self.path = path
        self.rehash = rehash
        self.lock = threading.Lock()
        self.entries: dict = {}
        self.dirty = False
        if path and path.exists():
            try:
                self.entries = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self.entries = {}

    def get(self, path: Path, size: int, mtime_ns: int) -> str | None:
        if self.rehash:
            return None
        with self.lock:
            entry = self.entries.get(str(path))
        if entry and entry.get("size") == size and entry.get("mtime_ns") == mtime_ns:
            return entry.get("sha256")
        return None

    def put(self, path: Path, size: int, mtime_ns: int, sha: str) -> None:
        with self.lock:
            self.entries[str(path)] = {"size": size, "mtime_ns": mtime_ns, "sha256": sha}
            self.dirty = True

    def save(self) -> None:
        if not self.path or not self.dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.entries, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)
        self.dirty = False


# ---------------------------------------------------------------------------------------------------------------
# Metadata: the game version, the packs, PE version resources.


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
    return ""


def packs(game: Path) -> list[str]:
    return sorted(p.name for p in game.iterdir() if p.is_dir() and PACK_RE.fullmatch(p.name))


def pe_version(path: Path) -> dict:
    """Read FileVersion and ProductVersion from the version resource of a PE file. Read only the headers and .rsrc."""
    try:
        with open(path, "rb") as f:
            dos = f.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                return {}
            pe_off = struct.unpack_from("<I", dos, 0x3C)[0]
            f.seek(pe_off)
            head = f.read(24)
            if head[:4] != b"PE\0\0":
                return {}
            sections, opt_size = struct.unpack_from("<H12xH", head, 6)
            opt = f.read(opt_size)
            magic = struct.unpack_from("<H", opt, 0)[0]
            dirs = 96 if magic == 0x10B else 112
            if len(opt) < dirs + 3 * 8:
                return {}
            rsrc_rva, _rsrc_size = struct.unpack_from("<II", opt, dirs + 2 * 8)
            if not rsrc_rva:
                return {}
            table = f.read(40 * sections)
            for i in range(sections):
                vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", table, i * 40 + 8)
                if vaddr <= rsrc_rva < vaddr + max(vsize, rsize):
                    base_rva, base_ptr, span = vaddr, rptr, min(max(vsize, rsize), MAX_RSRC)
                    break
            else:
                return {}
            f.seek(base_ptr)
            data = f.read(span)
    except OSError:
        return {}

    def at(rva: int) -> int:
        return rva - base_rva

    root = at(rsrc_rva)

    def entries(offset: int):
        named, ids = struct.unpack_from("<HH", data, offset + 12)
        for k in range(named + ids):
            name, target = struct.unpack_from("<II", data, offset + 16 + k * 8)
            yield name, target

    try:
        node = None
        for name, target in entries(root):
            if name == 16 and target & 0x80000000:
                node = root + (target & 0x7FFFFFFF)
                break
        if node is None:
            return {}
        # Go down to the first leaf: the version resource has one name and usually one language.
        while True:
            first = next(entries(node), None)
            if first is None:
                return {}
            target = first[1]
            if target & 0x80000000:
                node = root + (target & 0x7FFFFFFF)
                continue
            leaf_rva, leaf_size = struct.unpack_from("<II", data, root + target)
            blob = data[at(leaf_rva): at(leaf_rva) + leaf_size]
            break
    except (struct.error, IndexError):
        return {}
    result = {}
    fixed = blob.find(b"\xbd\x04\xef\xfe")
    if fixed >= 0 and fixed + 24 <= len(blob):
        fms, fls, pms, pls = struct.unpack_from("<IIII", blob, fixed + 8)
        result["file_version_fixed"] = f"{fms >> 16}.{fms & 0xFFFF}.{fls >> 16}.{fls & 0xFFFF}"
        result["product_version_fixed"] = f"{pms >> 16}.{pms & 0xFFFF}.{pls >> 16}.{pls & 0xFFFF}"
    for key, label in (("FileVersion", "file_version"), ("ProductVersion", "product_version")):
        marker = (key + "\0").encode("utf-16-le")
        pos = blob.find(marker)
        if pos < 0:
            continue
        pos += len(marker)
        pos += (-pos) % 4
        end = pos
        while end + 1 < len(blob) and blob[end:end + 2] != b"\0\0":
            end += 2
        value = blob[pos:end].decode("utf-16-le", "replace").strip()
        if value:
            result[label] = value
    return result


# ---------------------------------------------------------------------------------------------------------------
# The manifest of the game folder.


def kind_of(rel: str) -> str:
    low = rel.lower()
    if low.endswith((".exe", ".dll", ".pyd")):
        return "binary"
    if low.endswith(".zip"):
        return "python" if "/simulation/gameplay/" in low or low.startswith("game/bin/python/") else "zip"
    if low.endswith(".package"):
        return "package"
    if low.endswith((".ini", ".cfg", ".sgr", ".txt", ".xml", ".json")):
        return "config"
    return "data"


def must_hash(rel: str, size: int, limit: int) -> bool:
    return kind_of(rel) in ("binary", "python", "config") or size <= limit


def game_files(game: Path) -> list[str]:
    """Every file in the game folder, as a posix path relative to it. The tool reads them; it never writes them."""
    found = []
    for dirpath, dirnames, filenames in os.walk(game):
        dirnames.sort()
        for name in filenames:
            found.append((Path(dirpath) / name).relative_to(game).as_posix())
    return sorted(found)


def file_entry(game: Path, rel: str, cache: HashCache, known: dict | None, stat_only: bool, limit: int) -> dict:
    path = game / rel
    st = path.stat()
    size, mtime_ns = st.st_size, st.st_mtime_ns
    mtime = datetime.datetime.fromtimestamp(mtime_ns / 1e9, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = {"size": size, "mtime": mtime, "kind": kind_of(rel)}
    sha = cache.get(path, size, mtime_ns)
    if sha is None and known and known.get("size") == size and known.get("mtime") == mtime and not cache.rehash:
        sha = known.get("sha256")
    if sha is None and (stat_only or not (cache.rehash or must_hash(rel, size, limit))):
        sha = "?"
    if sha is None:
        if size > (256 << 20):
            say(f"  hash {rel} ({size / (1 << 30):.2f} GiB)")
        sha = sha256_file(path)
        cache.put(path, size, mtime_ns, sha)
    entry["sha256"] = sha
    if rel.lower().endswith((".exe", ".dll")):
        entry.update(pe_version(path))
    return entry


def ours_entry(game: Path) -> dict:
    result = {}
    for rel in sorted(OURS):
        path = game / rel
        if not path.exists():
            continue
        data = path.read_bytes()
        st = path.stat()
        result[rel] = {
            "size": st.st_size,
            "mtime": datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "sha256": hashlib.sha256(data).hexdigest(),
            "mod_loader": LOADER_MARKER in data,
        }
    for folder in OURS_FOLDERS:
        root = game / folder
        if root.is_dir():
            for p in sorted(root.rglob("*")):
                if p.is_file():
                    result[p.relative_to(game).as_posix()] = {"size": p.stat().st_size,
                                                              "sha256": sha256_file(p)}
    return result


def make_manifest(game: Path, user: Path, cache: HashCache, previous: dict | None, stat_only: bool = False,
                  limit: int = HASH_LIMIT) -> tuple[dict, dict]:
    """Return the manifest of the game folder, and the separate record of our own files in it."""
    if not (game / "Game" / "Bin").exists():
        raise SystemExit(f"{game} is not a game folder of The Sims 4 (no Game\\Bin)")
    old_files = (previous or {}).get("files", {})
    files = {}
    for rel in game_files(game):
        if rel in OURS or rel.startswith(OURS_FOLDERS):
            continue
        files[rel] = file_entry(game, rel, cache, old_files.get(rel), stat_only, limit)
    version_file = user / "GameVersion.txt"
    manifest = {
        "folder": str(game),
        "version": read_version(version_file) if version_file.exists() else "",
        "exe_version": files.get("Game/Bin/TS4_x64.exe", {}).get("product_version", ""),
        "packs": packs(game),
        "files": files,
    }
    ours = ours_entry(game)
    for rel, info in ours.items():
        if rel in OURS and not info["mod_loader"]:
            say(f"WARNING: {rel} is not our mod loader; it is not a game file either")
    return manifest, ours


def dump_json(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------------------------------------------
# Compare manifests.


def compare(old: dict | None, new: dict) -> dict:
    old_files = (old or {}).get("files", {})
    new_files = new.get("files", {})
    changed, touched = [], []
    for rel in sorted(set(old_files) & set(new_files)):
        a, b = old_files[rel], new_files[rel]
        if "?" in (a.get("sha256"), b.get("sha256")):
            if a.get("size") != b.get("size") or a.get("mtime") != b.get("mtime"):
                changed.append(rel)
        elif a.get("sha256") != b.get("sha256"):
            changed.append(rel)
        elif a != b:
            touched.append(rel)
    return {
        "changed": changed,
        "touched": touched,
        "new": sorted(set(new_files) - set(old_files)),
        "removed": sorted(set(old_files) - set(new_files)),
    }


def short_list(label: str, names: list[str]) -> list[str]:
    if not names:
        return []
    lines = [f"  {label} ({len(names)}):"]
    lines += [f"    {n}" for n in names[:LIST_LIMIT]]
    if len(names) > LIST_LIMIT:
        lines.append(f"    ... and {len(names) - LIST_LIMIT} more")
    return lines


def ids(manifest: dict | None) -> str:
    if not manifest:
        return "none"
    return f"version {manifest.get('version', '') or '?'}, {len(manifest.get('packs', []))} packs"


# ---------------------------------------------------------------------------------------------------------------
# The tracking repository.


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8",
                          check=check)


README = """# The Sims 4: game versions

The hashes and metadata of each version of The Sims 4 that we saw. `tools/game_builds.py record` in
`<workspace>\\projects\\ts4_research` writes this repository; the skill `ts4-game-builds` tells when and what to do
after a change.

- `ea/manifest.json`: the game folder: the version, the packs, and the SHA-256, size,
  time and PE version of each game file. A large package has the size and time only (`"sha256": "?"`).
- `ea/ours.json`: our own files in the game folder (the DLL of the mod loader and its mods folder). They are not game
  files.

No game file goes in this repository. The tag `ts4-<version>` marks the first record of each version.
"""


def ensure_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    if not (repo / ".git").exists():
        git(repo, "init", "-q", "-b", "main")
    readme = repo / "README.md"
    if not readme.exists():
        readme.write_text(README, encoding="utf-8", newline="\n")


def head_manifest(repo: Path, rel: str, rev: str = "HEAD") -> dict | None:
    if not (repo / ".git").exists():
        return None
    out = git(repo, "show", f"{rev}:{rel}", check=False)
    if out.returncode != 0:
        return None
    return json.loads(out.stdout)


def commit_message(old: dict | None, new: dict, change: dict, ours_changed: bool) -> str:
    if old is None:
        subject = f"Record The Sims 4 version {new['version']}"
        body = [f"The first record has {len(new['files'])} files and {len(new['packs'])} packs."]
    else:
        if old.get("version") != new.get("version"):
            subject = f"Record The Sims 4 version {new['version']}"
        elif old.get("packs") != new.get("packs"):
            subject = f"Record a change of the packs in version {new['version']}"
        elif any(change[k] for k in ("changed", "new", "removed")):
            subject = f"Record changed game files in version {new['version']}"
        elif ours_changed:
            subject = "Record a different mod loader in the game folder"
        else:
            subject = "Record the times of the game files"
        body = []
        if any(change.values()):
            body.append(f"The game changed: {ids(old)} -> {ids(new)}.")
        for pack in sorted(set(new.get("packs", [])) - set(old.get("packs", []))):
            body.append(f"- new pack: {pack}")
        for pack in sorted(set(old.get("packs", [])) - set(new.get("packs", []))):
            body.append(f"- removed pack: {pack}")
        for label in ("changed", "new", "removed"):
            for rel in change[label]:
                body.append(f"- {label}: {rel}")
        if ours_changed:
            body.append("ea/ours.json records a different mod loader.")
    if len(body) > BODY_LIMIT:
        body = body[:BODY_LIMIT] + [f"- and {len(body) - BODY_LIMIT} more lines; use game_builds.py diff."]
    return subject[:72] + "\n\n" + ("\n".join(body) + "\n\n" if body else "") + TRAILER + "\n"


def cmd_record(args) -> int:
    repo = Path(args.repo)
    cache = HashCache(Path(args.cache) if args.cache else None, args.rehash)
    ensure_repo(repo)
    old = head_manifest(repo, "ea/manifest.json")
    try:
        manifest, ours = make_manifest(Path(args.game), Path(args.user), cache, old, limit=args.hash_limit)
    finally:
        cache.save()
    change = compare(old, manifest)
    old_ours = head_manifest(repo, "ea/ours.json")
    (repo / "ea").mkdir(exist_ok=True)
    (repo / "ea" / "manifest.json").write_text(dump_json(manifest), encoding="utf-8", newline="\n")
    ours_path = repo / "ea" / "ours.json"
    ours_changed = False
    if ours:
        ours_path.write_text(dump_json(ours), encoding="utf-8", newline="\n")
        ours_changed = old_ours != ours
    elif ours_path.exists():
        ours_path.unlink()
        ours_changed = True
    hashed = sum(1 for f in manifest["files"].values() if f["sha256"] != "?")
    say(f"ea: {ids(manifest)}, {len(manifest['files'])} files ({hashed} hashed)")
    git(repo, "add", "-A", "--", "README.md", "ea")
    if git(repo, "diff", "--cached", "--quiet", check=False).returncode == 0:
        say("no change; nothing to commit")
    else:
        msg_file = repo / ".git" / "GAME_BUILDS_MSG"
        msg_file.write_text(commit_message(old, manifest, change, ours_changed), encoding="utf-8", newline="\n")
        git(repo, "commit", "-q", "-F", str(msg_file))
        msg_file.unlink()
        say("committed: " + git(repo, "log", "-1", "--format=%h %s").stdout.strip())
    if manifest["version"]:
        tag = f"ts4-{manifest['version']}"
        if git(repo, "rev-parse", "-q", "--verify", f"refs/tags/{tag}", check=False).returncode != 0:
            git(repo, "tag", tag)
            say(f"tagged {tag}")
    return 0


def cmd_check(args) -> int:
    repo = Path(args.repo)
    cache = HashCache(Path(args.cache) if args.cache else None)
    old = head_manifest(repo, "ea/manifest.json")
    # check writes nothing: not the repository, not the hash cache.
    new, ours = make_manifest(Path(args.game), Path(args.user), cache, old, stat_only=args.quick,
                              limit=args.hash_limit)
    if old is None:
        say("ea: no record yet; run game_builds.py record")
        return 1
    c = compare(old, new)
    old_ours = head_manifest(repo, "ea/ours.json") or {}
    for rel, info in ours.items():
        same = "as recorded" if old_ours.get(rel, {}).get("sha256") == info["sha256"] else "not recorded"
        say(f"ea: ours {rel} ({same})")
    files_changed = bool(c["changed"] or c["new"] or c["removed"])
    if old.get("version") != new.get("version") or files_changed:
        say(f"ea: CHANGED since the last record: {ids(old)} -> {ids(new)}")
        for line in short_list("changed", c["changed"]) + short_list("new", c["new"]) + short_list("removed",
                                                                                                   c["removed"]):
            say(line)
        return 1
    if old.get("packs") != new.get("packs"):
        say(f"ea: the packs changed: {', '.join(old.get('packs', []))} -> {', '.join(new.get('packs', []))}")
        return 2
    extra = f" ({len(c['touched'])} files have a new time only)" if c["touched"] else ""
    say(f"ea: same as the last record, {ids(new)}{extra}")
    return 0


def cmd_diff(args) -> int:
    repo = Path(args.repo)
    old = head_manifest(repo, "ea/manifest.json", args.rev_a)
    new = head_manifest(repo, "ea/manifest.json", args.rev_b)
    if old is None or new is None:
        say(f"ea: no record in {args.rev_a if old is None else args.rev_b}")
        return 1
    c = compare(old, new)
    say(f"ea: {ids(old)} -> {ids(new)}")
    if old.get("exe_version") != new.get("exe_version"):
        say(f"  TS4_x64.exe {old.get('exe_version')} -> {new.get('exe_version')}")
    for pack in sorted(set(new.get("packs", [])) ^ set(old.get("packs", []))):
        say(f"  {'new' if pack in new.get('packs', []) else 'removed'} pack {pack}")
    for rel in c["changed"]:
        a, b = old["files"][rel], new["files"][rel]
        say(f"  changed {rel} ({b.get('kind', '?')}, {a['size']} -> {b['size']} bytes ({b['size'] - a['size']:+d}))")
    for rel in c["new"]:
        say(f"  new     {rel} ({new['files'][rel].get('size', '?')} bytes)")
    for rel in c["removed"]:
        say(f"  removed {rel}")
    if c["touched"]:
        say(f"  {len(c['touched'])} files have a new time only")
    return 0


# ---------------------------------------------------------------------------------------------------------------
# Self-test on a temporary folder of fake files.


def self_test() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="game-builds-test-"))
    try:
        game, user, repo = tmp / "game", tmp / "user", tmp / "repo"
        (game / "Game" / "Bin").mkdir(parents=True)
        (game / "Data" / "Simulation" / "Gameplay").mkdir(parents=True)
        (game / "EP01").mkdir()
        user.mkdir()
        (user / "GameVersion.txt").write_bytes(struct.pack("<I", 13) + b"1.128.90.1030")
        (game / "Game" / "Bin" / "TS4_x64.exe").write_bytes(b"MZ not a real exe")
        (game / "Game" / "Bin" / "Simulation_x64.dll").write_bytes(b"MZ code one")
        (game / "Data" / "Simulation" / "Gameplay" / "simulation.zip").write_bytes(b"PK one")
        (game / "EP01" / "Big.package").write_bytes(b"DBPF" + b"\0" * 64)
        (game / "Game" / "Bin" / "version.dll").write_bytes(b"MZ " + LOADER_MARKER)
        base = ["--game", str(game), "--user", str(user), "--repo", str(repo), "--cache", str(tmp / "cache.json"),
                "--hash-limit", "16"]
        os.environ["GIT_CONFIG_PARAMETERS"] = "'user.name=test' 'user.email=test@example.com'"

        def run(*argv: str) -> int:
            return main([*argv, *base])

        assert read_version(user / "GameVersion.txt") == "1.128.90.1030"
        assert kind_of("Data/Simulation/Gameplay/simulation.zip") == "python"
        assert kind_of("EP01/Big.package") == "package"
        assert pe_version(game / "Game" / "Bin" / "TS4_x64.exe") == {}
        assert run("check") == 1, "no record yet"
        assert run("record") == 0
        log = git(repo, "log", "--format=%s").stdout.splitlines()
        assert log == ["Record The Sims 4 version 1.128.90.1030"], log
        assert git(repo, "tag").stdout.split() == ["ts4-1.128.90.1030"]
        manifest = json.loads((repo / "ea" / "manifest.json").read_text())
        assert "Game/Bin/version.dll" not in manifest["files"]
        assert manifest["packs"] == ["EP01"] and manifest["version"] == "1.128.90.1030"
        assert manifest["files"]["EP01/Big.package"]["sha256"] == "?", "a large package gets no hash"
        assert manifest["files"]["Game/Bin/Simulation_x64.dll"]["sha256"] != "?"
        assert json.loads((repo / "ea" / "ours.json").read_text())["Game/Bin/version.dll"]["mod_loader"] is True
        assert run("check") == 0
        assert run("record") == 0
        assert len(git(repo, "log", "--format=%s").stdout.splitlines()) == 1, "no change must make no commit"
        (game / "GP01").mkdir()
        assert run("check") == 2, "only the packs changed"
        (game / "GP01").rmdir()
        # An update: new code and a new version.
        (game / "Game" / "Bin" / "Simulation_x64.dll").write_bytes(b"MZ code two, longer")
        (user / "GameVersion.txt").write_bytes(struct.pack("<I", 13) + b"1.129.10.1020")
        assert run("check", "--quick") == 1
        assert run("check") == 1
        assert run("record") == 0
        assert git(repo, "log", "-1", "--format=%s").stdout.strip() == "Record The Sims 4 version 1.129.10.1020"
        assert "- changed: Game/Bin/Simulation_x64.dll" in git(repo, "log", "-1", "--format=%b").stdout
        assert sorted(git(repo, "tag").stdout.split()) == ["ts4-1.128.90.1030", "ts4-1.129.10.1020"]
        assert run("diff", "ts4-1.128.90.1030", "ts4-1.129.10.1020") == 0
        cached = HashCache(tmp / "cache.json")
        st = (game / "Game" / "Bin" / "Simulation_x64.dll").stat()
        assert cached.get(game / "Game" / "Bin" / "Simulation_x64.dll", st.st_size, st.st_mtime_ns) == sha256_file(
            game / "Game" / "Bin" / "Simulation_x64.dll")
        system_dll = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll"
        if system_dll.exists():
            assert pe_version(system_dll).get("file_version_fixed"), "the PE reader found no version"
        say("self-test: OK")
        return 0
    finally:
        os.environ.pop("GIT_CONFIG_PARAMETERS", None)
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="run the tests on fake files and stop")
    options = (("--game", str(GAME) if GAME else None), ("--user", str(USER_FOLDER)), ("--repo", str(TRACKING_REPO)),
               ("--cache", str(HASH_CACHE)))
    for opt, default in options:
        parser.add_argument(opt, default=default)
    parser.add_argument("--hash-limit", type=int, default=HASH_LIMIT)
    sub = parser.add_subparsers(dest="command")
    rec = sub.add_parser("record", help="write the manifest and commit it when something changed")
    rec.add_argument("--rehash", action="store_true", help="read every file again, packages too; ignore the cache")
    chk = sub.add_parser("check", help="compare the game with the last record; write nothing")
    chk.add_argument("--quick", action="store_true", help="compare only sizes, times and ids; read no file")
    dif = sub.add_parser("diff", help="list the changed files between two records")
    dif.add_argument("rev_a")
    dif.add_argument("rev_b", nargs="?", default="HEAD")
    # The global options can also come after the command.
    for p in (rec, chk, dif):
        for opt, _ in options:
            p.add_argument(opt, default=argparse.SUPPRESS)
        p.add_argument("--hash-limit", type=int, default=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.command in ("record", "check") and not args.game:
        sys.exit(NO_GAME)
    if args.command == "record":
        return cmd_record(args)
    if args.command == "check":
        return cmd_check(args)
    if args.command == "diff":
        return cmd_diff(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
