#!/usr/bin/env python3
"""Structural validation of the Sigma pack. Requires pysigma, no network.

Deliberately not part of the pytest suite: pysigma is an optional dependency
and a missing optional dependency should not turn into a failing test run.
"""
from __future__ import annotations

import sys
from pathlib import Path

RULES = Path(__file__).resolve().parents[1] / "detection" / "sigma"


def main() -> int:
    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        print("pysigma not installed: pip install pysigma", file=sys.stderr)
        return 2

    failures = 0
    for path in sorted(RULES.glob("*.yml")):
        try:
            rule = SigmaCollection.load_ruleset([path]).rules[0]
            print(f"OK    {path.name}  [{rule.logsource.product}/{rule.logsource.service}]")
        except Exception as exc:
            failures += 1
            print(f"FAIL  {path.name}: {type(exc).__name__}: {exc}")
    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
