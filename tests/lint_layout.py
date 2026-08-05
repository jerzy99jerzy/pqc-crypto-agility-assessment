#!/usr/bin/env python3
"""Check the README's repository map against the tree.

The map went stale for four sprints without anyone noticing: it still showed
`collectors/`, `active/`, `scoring/`, `inventory/` and `reporting/` as
top-level packages after they moved under `ananke/` in v0.10.0, and it was
missing eight files added since. Caught by a reader, not by a review, which is
the same way the stale limitations claim was caught in v0.13.1.

The same answer applies: a claim the repository makes about itself should be
executable. This is the layout half of `lint_limitations.py`.

Two directions, both fail the build:

- a path drawn in the map that does not exist on disk, which is what a rename
  or a refactor leaves behind;
- a path on disk at map depth that the map does not mention, which is what a
  new module leaves behind.

Not every file is in scope. The map is a reader's orientation, not an
inventory, so leaf files inside `detection/`, `config/` and `data/` are
represented by their directory. What is in scope is every directory the map
draws, and every Python module under `ananke/` and `tests/`, because those are
the paths a reader navigates by.

Run through `make lint-layout`.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

MAP_RE = re.compile(r"```\n(pqc-crypto-agility-assessment/.*?)```", re.S)
ENTRY_RE = re.compile(r"[├└]── ([A-Za-z0-9_.\-]+/?)")

# Directories whose leaves the map represents by the directory itself.
SUMMARISED = {"detection", "config", "data", "tests/fixtures", ".github"}

SKIP_PARTS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv",
              "dist", "build", ".ruff_cache", ".mypy_cache"}

# A drawn path must exist on disk *unless git ignores it*. Derived, not
# enumerated, and that distinction is the whole point of this block.
#
# The hand-written version of this exemption failed in CI twice: first on
# `docs/report.md`, which is generated, then on `data/raw`, which is created at
# runtime and git-ignored. Each time the fix was to add one more literal, which
# is precisely the maintenance trap that the hand-maintained disclosure
# allowlist fell into in sprint 8 and that was solved there by deriving from
# `git ls-files`. Applying the same answer here rather than a third literal.
#
# The rule reads cleanly: if the repository ignores a path, a clean checkout
# will not have it, and the map is still right to draw it - a reader needs to
# know where output lands. If the repository does not ignore it and it is
# missing, that is drift.
# Output whose tracking status legitimately differs between clones: generated
# on demand, committed in one working copy and absent in another. Ignoring is
# not the right signal for these, so they are listed. Kept short and separate
# from the derived rule so the two mechanisms stay distinguishable.
GENERATED = {"report.md", "report.html", "sectors.json",
             "hndl_sector_scores.json", "estate_completeness.json",
             "key_inventory.json"}


def _git_ignores(name: str) -> bool:
    """True when git would ignore a path with this name anywhere in the tree.

    Fails closed: if git is unavailable the answer is False, so a missing path
    is reported rather than silently excused.
    """
    # Both forms of every candidate. A pattern written `data/raw/` matches a
    # directory, and once the directory is gone git cannot tell the path was
    # one, so the bare form misses exactly in the situation this check exists
    # for: a clean checkout where the path was never created.
    candidates = []
    for prefix in ("", "data/", "docs/"):
        candidates += [f"{prefix}{name}", f"{prefix}{name}/"]
    for candidate in candidates:
        try:
            result = subprocess.run(
                ["git", "-C", str(ROOT), "check-ignore", "-q", candidate],
                capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return False
        if result.returncode == 0:
            return True
    return False


def _mapped_names() -> set[str]:
    block = MAP_RE.search(README.read_text(encoding="utf-8"))
    if not block:
        print("FAIL  no repository map found in README.md")
        sys.exit(1)
    return {m.rstrip("/") for m in ENTRY_RE.findall(block.group(1))}


def _expected_names() -> set[str]:
    """Names the map is expected to mention: every tracked directory, plus every
    Python module under the package and the test directory."""
    expected: set[str] = set()
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        parts = rel.parts
        if SKIP_PARTS & set(parts) or "egg-info" in str(rel):
            continue
        if any(str(rel).startswith(s + "/") for s in SUMMARISED):
            continue
        if path.is_dir():
            if not parts[0].startswith("."):
                expected.add(path.name)
        elif parts[0] in ("ananke", "tests") and path.suffix in (".py", ".yaml"):
            # `__init__.py` marks a package rather than telling a reader
            # anything; the map draws the package instead.
            if path.name != "__init__.py":
                expected.add(path.name)
    return expected


def main() -> int:
    mapped = _mapped_names()
    expected = _expected_names()

    drawn_but_absent = sorted(
        name for name in mapped - GENERATED
        if not _git_ignores(name)
        if not any(p.name == name for p in ROOT.rglob(name)
                   if not (SKIP_PARTS & set(p.relative_to(ROOT).parts)))
    )
    present_but_undrawn = sorted(expected - mapped)

    failures = []
    for name in drawn_but_absent:
        failures.append(f"map draws {name!r}, which is not in the tree - "
                        "a rename or removal left the map behind")
    for name in present_but_undrawn:
        failures.append(f"{name!r} exists and the map does not mention it - "
                        "add it, or add its directory to SUMMARISED if the map "
                        "should represent it by its parent")

    for f in failures:
        print(f"FAIL  {f}")
    if not failures:
        print(f"OK    repository map matches the tree "
              f"({len(mapped)} entries checked)")
    print(f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
