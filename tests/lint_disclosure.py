#!/usr/bin/env python3
"""Disclosure lint for everything that is committed.

Runs the same guard the writers use, but from the outside, over files already
on disk. The writers can be bypassed by editing a JSON by hand; this cannot.

Checks:
  data/aggregates/*.json   structural guard, forbidden keys and host-like strings
  docs/*.md                prose scan, minus declared reference hosts
  config/targets.yaml      must not be tracked by git

Exit code 1 on any violation, so it works as a CI gate or a pre-commit hook.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from ananke.collectors.disclosure import (  # noqa: E402
    DisclosureViolation,
    assert_no_host_identifiers,
    scan_text,
)


def reference_hosts() -> set[str]:
    path = REPO_ROOT / "config" / "reference_hosts.yaml"
    if not path.exists():
        return set()
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        str(h).strip().lower()
        for category in ("self", "reference")
        for h in (doc.get(category) or [])
    }


def check_aggregates() -> list[str]:
    problems = []
    for path in sorted((REPO_ROOT / "data" / "aggregates").glob("*.json")):
        try:
            assert_no_host_identifiers(json.loads(path.read_text(encoding="utf-8")))
            print(f"OK    {path.relative_to(REPO_ROOT)}")
        except (DisclosureViolation, json.JSONDecodeError) as exc:
            problems.append(f"{path.relative_to(REPO_ROOT)}: {exc}")
    return problems


def check_docs(allowed: set[str]) -> list[str]:
    problems = []
    prose = sorted((REPO_ROOT / "docs").glob("*.md"))
    prose += [REPO_ROOT / f for f in ("README.md", "TODO.md", "CONTRIBUTING.md")
              if (REPO_ROOT / f).exists()]
    for path in prose:
        found = sorted(set(scan_text(path.read_text(encoding="utf-8"), extra_allowed=allowed)))
        if found:
            problems.append(f"{path.relative_to(REPO_ROOT)}: host-like tokens {found}")
        else:
            print(f"OK    {path.relative_to(REPO_ROOT)}")
    return problems


def check_targets_untracked() -> list[str]:
    target = REPO_ROOT / "config" / "targets.yaml"
    if not target.exists():
        return []
    try:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(target.relative_to(REPO_ROOT))],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return []  # not a git checkout; nothing to assert
    if result.returncode == 0:
        return ["config/targets.yaml is tracked by git; it must stay ignored"]
    print("OK    config/targets.yaml present and untracked")
    return []


def main() -> int:
    allowed = reference_hosts()
    problems = check_aggregates() + check_docs(allowed) + check_targets_untracked()
    for p in problems:
        print(f"FAIL  {p}")
    print(f"{len(problems)} violation(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
