#!/usr/bin/env python3
"""Structural checks over `detection/spl/`.

Deliberately not a parser. There is no offline SPL parser worth trusting, and
writing half of one would produce a validator that passes broken searches while
implying they were checked. That is the failure mode this project treats as
worse than having no check at all.

What can be verified without an indexer is discipline, so that is what is
verified: every search carries its question, its source assumption, and an
explicit validation status; the milestone is referenced as a macro rather than
retyped; and no search silently drops the `unknown` state, because a filter
written as `="true"` reports an unrecognised algorithm as safe and that is the
one defect class this whole repository exists to avoid.

Run through `make spl-check`. Exits non-zero on any failure.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

SPL_DIR = Path(__file__).resolve().parents[1] / "detection" / "spl"

REQUIRED_HEADER = (
    ("question", re.compile(r"^\*\s*Question:", re.M)),
    ("source assumption", re.compile(r"^\*\s*Source:", re.M | re.I)),
    ("validation status", re.compile(r"^\*\s*Validation status:\s*\[(measured|inference)\]", re.M)),
)

# A hard-coded milestone in a query is a fifth place the date has to be changed.
HARDCODED_MILESTONE = re.compile(r'"20(2[89]|3[0-9])-\d{2}-\d{2}"')
MACRO_MILESTONE = re.compile(r"`pqc_milestone`")

# Reporting only the certain-positive case hides the unknown state.
UNSAFE_TRISTATE = re.compile(r'quantum_vulnerable\s*=\s*"true"')


def check(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    problems = []

    for label, pattern in REQUIRED_HEADER:
        if not pattern.search(text):
            problems.append(f"missing {label} in the header comment")

    # Content checks run over the search body only. Running them over the whole
    # file flagged this repository's own comment warning against the
    # anti-pattern, which is the classic way a linter teaches people to stop
    # documenting the thing it checks for.
    body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("*"))

    if HARDCODED_MILESTONE.search(body) and not MACRO_MILESTONE.search(body):
        problems.append("milestone date hard-coded; use the `pqc_milestone` macro")

    if UNSAFE_TRISTATE.search(body):
        problems.append(
            'filters on quantum_vulnerable="true" and so drops "unknown"; '
            'an unrecognised algorithm must not be reported as safe')
    if body.count("(") != body.count(")"):
        problems.append("unbalanced parentheses in the search body")
    if body.count('"') % 2:
        problems.append("odd number of double quotes in the search body")
    if not body.strip():
        problems.append("no search body, only comments")

    return problems


def main() -> int:
    files = sorted(SPL_DIR.glob("*.spl"))
    if not files:
        print("no .spl files found", file=sys.stderr)
        return 1

    failures = 0
    for path in files:
        problems = check(path)
        if problems:
            failures += 1
            print(f"FAIL  {path.name}")
            for p in problems:
                print(f"      {p}")
        else:
            print(f"OK    {path.name}")
    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
