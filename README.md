# The Sims 4 mods: research tools

Python tools that make and serve the Ghidra projects of the game, keep the function catalogue, and record each game
version. The details are in `docs/tools.md`.

This project runs a headless process of Ghidra and communicates with it using MCP via
[ghidra-mcp](https://github.com/LaurieWired/GhidraMCP). As The Sims 4 is constantly updating, this variant of
the Ghidra catalogue is version-aware with function decomps stored in a folder named after the game version similar
to other projects of mine. Git is used to keep track of the catalogue and the game versions.

Overall, this project reduces the amount of work needed to research work and optimises A.I token usage.

Here is an example directory structure for The Sims 4:

`ghidra-catalogue\TS4_x64_1.128.90.1030\fn\000AAE80.md` where `000AAE80` is the function address.

Each markdown file contains something similar to:

```md
---
address: "000AAE80"
binary: "TS4_x64_1.128.90.1030"
build: "TS4_x64_1.128.90.1030"
name: "EA::Sims4::ClientApp::Services::AudioSystemService::vfunc_6"
short_name: "vfunc_6"
signature: "undefined vfunc_6(void)"
size: "0x29a"
fetched: "2026-10-25"
status: "raw"
summary: ""
tags: []
---

## Analysis

...

## Comments

...

## Disassembly

...
```

## Build

Nothing to build. Requirements: Python 3.10 or later, and Ghidra (`GHIDRA_INSTALL_DIR`) for the Ghidra tools. The
tools find the workspace (the folder that holds `projects`) from `TS4_WORKSPACE`, or two folders above this
repository, and the game folder from `TS4_GAME` or the registry.

## Tests

Each Python tool has a self-test that needs no game and no Ghidra:

```bat
python tools\game_builds.py --self-test
python tools\ghidra\ghidra_builds.py --self-test
python tools\ghidra-catalogue\ghcat.py --self-test
python tools\ghidra-catalogue\check_commit_msg.py --self-test
```

## How to install

Nothing to install. To use the commit-msg hook in a repository:

```bat
python tools\ghidra-catalogue\check_commit_msg.py --install <repository>
```
