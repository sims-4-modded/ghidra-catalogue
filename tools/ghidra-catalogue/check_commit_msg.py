#!/usr/bin/env python3
# ******************************************************************************
# Copyright (c) 2026 Sims 4 mods developers
# ******************************************************************************
"""commit-msg check for the Sims 4 repositories and the Ghidra catalogue: the basic ASD-STE100 rules a script can test.

  check_commit_msg.py <message file>       the hook: exit 1 with the errors if the message breaks a rule
  check_commit_msg.py --install <repo>     write .git/hooks/commit-msg in a repository; the hook calls this file
  check_commit_msg.py --self-test
"""
import re
import sys
from pathlib import Path

# Words that STE does not approve, or that hide what changed. Use the approved word in brackets.
UNAPPROVED = {
    "tweak": "change", "tweaks": "change", "fixup": "correct", "refactor": "change", "cleanup": "remove",
    "misc": "name the change", "various": "name the change", "stuff": "name the thing", "wip": "complete it",
    "utilize": "use", "utilise": "use", "modify": "change", "implement": "add", "implemented": "added",
    "leverage": "use", "ensure": "make sure", "via": "through", "etc": "name the things",
}


def errors_of(text: str) -> list[str]:
    lines = [line.rstrip("\n") for line in text.splitlines() if not line.startswith("#")]
    while lines and not lines[-1].strip():
        lines.pop()
    errors = []
    subject = lines[0] if lines else ""
    if not subject.strip():
        errors.append("the subject line is empty")
    if len(subject) > 72:
        errors.append(f"the subject has {len(subject)} characters (72 is the maximum)")
    if subject.endswith("."):
        errors.append("the subject ends with a full stop")
    if subject and not subject[0].isupper():
        errors.append("the subject does not start with a capital letter")
    first = subject.split(" ", 1)[0] if subject else ""
    if first.lower().endswith("ing") or first.lower().endswith("ed"):
        errors.append(f"start the subject with an instruction verb (for example Add, Change, Remove), not '{first}'")
    if len(lines) > 1 and lines[1].strip():
        errors.append("put an empty line after the subject")
    for word in re.findall(r"[A-Za-z]+", " ".join(lines)):
        if word.lower() in UNAPPROVED:
            errors.append(f"'{word}' is not STE; use: {UNAPPROVED[word.lower()]}")
    for i, line in enumerate(lines[2:], 3):
        if not line.startswith("Co-Authored-By:") and len(re.findall(r"\w+", line)) > 25:
            errors.append(f"line {i} has more than 25 words (STE sentence limit)")
    return errors


def install(repo: Path) -> None:
    hooks = repo / ".git" / "hooks"
    if not hooks.is_dir():
        sys.exit(f"{repo} is not the main checkout of a git repository")
    script = Path(__file__).resolve().as_posix()
    (hooks / "commit-msg").write_text(f'#!/bin/sh\nexec python "{script}" "$1"\n', encoding="utf-8", newline="\n")
    print(f"installed {hooks / 'commit-msg'} -> {script}")


def self_test() -> None:
    good = "Add the server of the Ghidra project\n\n"
    assert errors_of(good) == [], errors_of(good)
    assert any("72" in e for e in errors_of("Add " + "x" * 80))
    assert any("full stop" in e for e in errors_of("Add the file."))
    assert any("instruction verb" in e for e in errors_of("Added the file"))
    assert any("not STE" in e for e in errors_of("Refactor the tool"))
    assert any("empty line" in e for e in errors_of("Add the file\nmore text"))
    print("self-test passed")


def main() -> None:
    if sys.argv[1:2] == ["--self-test"]:
        self_test()
        return
    if sys.argv[1:2] == ["--install"] and len(sys.argv) == 3:
        install(Path(sys.argv[2]))
        return
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    errors = errors_of(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if errors:
        sys.stderr.write("Commit message is not in STE:\n  - " + "\n  - ".join(errors) + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
