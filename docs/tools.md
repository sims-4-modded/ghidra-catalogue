# The research tools

Tools for the research of the native code of The Sims 4 (`TS4_x64.exe` and `Simulation_x64.dll`). The skills
`ts4-ghidra-catalogue` and `ts4-game-builds` tell when and how to use them.

`<workspace>` is the folder that holds `projects`. The tools find it from `TS4_WORKSPACE`, or as the folder two levels
above this repository. They find the game folder from `TS4_GAME`, or from the registry key that the EA app writes
(`HKLM\SOFTWARE\Maxis\The Sims 4`, value `Install Dir`). They write nothing in the game folder.

## The tools

| Tool | What it does |
|---|---|
| `tools/ghidra/ghidra_builds.py` | Makes one Ghidra project for each build (`<module>_<version>`), in `<workspace>\ghidra\<build>\ts4.gpr`. |
| `tools/ghidra/Ts4Prepare.java` | Moves the image base to `0x0` and writes each pointer of the data as an RVA (mode `rebase`). Names the vtables and virtual functions from the RTTI, and the C functions of the Python method tables (mode `name`). Writes `names.tsv`. |
| `tools/ghidra/ghidra-server.bat` | Serves one project without the GUI on `127.0.0.1:8083` (or `8084`), for the MCP server `ghidra-ts4` and `ghcat.py`. |
| `tools/ghidra/Ts4McpServer.java` | The server: the endpoints of the GhidraMCP plugin, `/build`, `/signature` and `/find_bytes`. |
| `tools/ghidra-catalogue/ghcat.py` | The catalogue in `<workspace>\ghidra-catalogue`: one file for each function that an agent studied. |
| `tools/ghidra-catalogue/check_commit_msg.py` | The commit-msg hook: the basic STE rules for a commit message. |
| `tools/game_builds.py` | Records the version, the packs and the hashes of the game files in `<workspace>\game-builds`. |

Each Python tool has a `--self-test` that needs no game and no Ghidra.

## A new project

1. Do `python tools/game_builds.py check`. If the version changed, do `record` first.
2. `Simulation_x64.dll`: do `python tools/ghidra/ghidra_builds.py new --module Simulation_x64`. The import and the
   analysis take approximately 7 minutes on 24 processors.
3. `TS4_x64.exe` is encrypted on disk by the activation wrapper of EA, so Ghidra cannot read the file. Give the tool
   a decrypted image: `ghidra_builds.py new --module TS4_x64 --image <path>`. The default path is
   `<workspace>\dump\TS4_<version>\TS4_x64.image.bin`. The image is a PE file in the memory layout: the file offset of
   each section is its RVA. Put `image.json` next to it with `exe_sha256`, the SHA-256 of the `TS4_x64.exe` that the
   image came from. The tool refuses an image of another exe, and an image that is still encrypted.
4. Serve the project: `tools\ghidra\ghidra-server.bat <build>`. Stop it with
   `curl -X POST http://127.0.0.1:8083/shutdown`.

## Ports

The Sims 4 uses the ports 8083 and 8084. The tools refuse the ports 8080 to 8082, which other projects use.

## Install the commit-msg hook

```sh
python tools/ghidra-catalogue/check_commit_msg.py --install <repository>
```
