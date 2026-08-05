#!/usr/bin/env python3
"""Consistency check between the limitations section and the repository.

The "What this assessment will not tell you" section is the part of the README
a reviewer reads most carefully, and until sprint 13 it was the only part of
the documentation nothing verified. The failure that motivated this check was
found by a question, not a review: the section claimed the assessment does not
see cryptography at rest while `detection/kql/arg_keyvault_key_inventory.kql`
had been enumerating stored asymmetric keys since sprint 4. Three code reviews
missed it, because all three looked at code, and this was a divergence between
the code and what the repository says about itself.

Truth cannot be automated; drift can. Every limitation bullet must be
registered here with probes, and the check is bidirectional:

- A bullet in the README with no registry entry fails: a new limitation must be
  registered consciously, with someone deciding what evidence would falsify it.
- A registry entry with no matching bullet fails: the registry cannot outlive
  the claim it was written for.
- `must_exist` probes assert the code property that makes a claim true is still
  present. "Does not probe third-party estate" is true because the active
  modality enforces an allowlist; if that enforcement disappears, the sentence
  upstairs is stale even though nobody edited it.
- `must_not_exist` probes assert the capability the claim denies has not
  quietly appeared. If PKCS#11 enumeration lands in `ananke/`, the HSM bullet
  needs rewriting before the build goes green again.

A claim with no probes carries a `note` saying why it is manually reviewed.
Silence is not an option; that is the point.

Run through `make lint-limitations`. Exits non-zero on any failure.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

SECTION_START = "## What this assessment will not tell you"
SECTION_END = re.compile(r"^## (?!What this assessment)")

# claim_key: a stable substring of the bullet, long enough to be unambiguous.
REGISTRY: list[dict] = [
    {
        "claim": "Bulk data encryption is not in migration scope",
        "must_exist": [("ananke/collectors/keys.py", r"_SYMMETRIC")],
        "note": "the exclusion is implemented, not just asserted: symmetric "
                "families are counted and classified not-vulnerable",
    },
    {
        "claim": "The key-wrapping layer is the real at-rest exposure",
        "must_exist": [
            ("ananke/collectors/keys.py", r"_WRAP_OPS"),
            ("detection/kql/arg_keyvault_key_inventory.kql", r"kty"),
        ],
        "note": "the bullet names pqc-keys and the ARG query as the counters; "
                "both must exist for the sentence to be honest",
    },
    {
        "claim": "Signing keys run on a different clock",
        "must_exist": [("ananke/collectors/keys.py", r"_SIGN_OPS")],
        "note": "the two-clock split is code, so its disappearance would make "
                "this bullet an unbacked promise",
    },
    {
        "claim": "Application-layer cryptography is not observable",
        "must_not_exist": [("ananke/**/*.py", r"\b(yara|binwalk|lief|capstone)\b")],
        "note": "if binary-analysis tooling ever lands, this bullet must be "
                "rewritten before the build passes",
    },
    {
        "claim": "does not see HSM internals beyond the attributes",
        "must_not_exist": [("ananke/**/*.py", r"\b(pkcs11|PyKCS11|C_FindObjects)\b")],
        "note": "PKCS#11 enumeration appearing in the tree falsifies 'beyond "
                "the attributes a key management API exposes'",
    },
    {
        "claim": "does not see internal PKI, except indirectly",
        "must_exist": [("detection/kql/mde_certificate_inventory_beyond_2030.kql",
                        r"DeviceTvmCertificateInfo")],
        "note": "the 'except indirectly' clause points at the endpoint "
                "inventory query; if that query goes, the qualifier goes",
    },
    {
        "claim": "does not see code, embedded libraries, or pinned certificates",
        "note": "manually reviewed: no probe distinguishes reading a binary "
                "from reading a certificate file by pattern alone",
    },
    {
        "claim": "negotiated key exchange group of third-party services",
        "must_exist": [("ananke/active/handshake_demo.py", r"allowlist|reference")],
        "note": "the claim is true because the active modality is gated to "
                "self/reference hosts; the gate must remain visible in code",
    },
    {
        "claim": "A certificate that uses RSA says nothing",
        "note": "manually reviewed: a statement about TLS layering, not about "
                "this repository's capabilities",
    },
]


def _bullets() -> list[str]:
    lines = README.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index(SECTION_START)
    except ValueError:
        print(f"FAIL  section heading not found: {SECTION_START!r}")
        sys.exit(1)
    out = []
    for line in lines[start + 1:]:
        if SECTION_END.match(line):
            break
        if line.startswith("- "):
            out.append(line[2:].strip())
    return out


def _probe_exists(pattern: str, regex: str) -> bool:
    rx = re.compile(regex)
    for path in sorted(ROOT.glob(pattern)):
        if path.is_file() and rx.search(
                path.read_text(encoding="utf-8", errors="replace")):
            return True
    # A glob matching nothing, or no file containing the regex, is a negative.
    # For must_exist that is a failure (the evidence file was removed, which is
    # exactly the drift to catch); for must_not_exist it is a pass.
    return False


def main() -> int:
    bullets = _bullets()
    failures: list[str] = []

    # 1. every bullet is registered
    for bullet in bullets:
        if not any(entry["claim"] in bullet for entry in REGISTRY):
            failures.append(
                f"unregistered limitation bullet: {bullet[:70]!r} - register "
                "it in tests/lint_limitations.py with probes or an explicit "
                "manual-review note")

    # 2. every registry entry still has its bullet
    for entry in REGISTRY:
        if not any(entry["claim"] in bullet for bullet in bullets):
            failures.append(
                f"registry entry with no matching README bullet: "
                f"{entry['claim']!r} - the claim was removed or reworded; "
                "update the registry in the same commit")
            continue

        for pattern, regex in entry.get("must_exist", []):
            if not _probe_exists(pattern, regex):
                failures.append(
                    f"claim {entry['claim']!r}: supporting evidence missing - "
                    f"no match for /{regex}/ under {pattern}. The property "
                    "that makes this sentence true is gone; rewrite the "
                    "sentence or restore the property")

        for pattern, regex in entry.get("must_not_exist", []):
            if _probe_exists(pattern, regex):
                failures.append(
                    f"claim {entry['claim']!r}: contradicted - /{regex}/ found "
                    f"under {pattern}. The capability this bullet denies now "
                    "exists; rewrite the bullet before the build goes green")

    for f in failures:
        print(f"FAIL  {f}")
    for entry in REGISTRY:
        if not failures:
            probes = len(entry.get("must_exist", [])) + len(entry.get("must_not_exist", []))
            kind = f"{probes} probe(s)" if probes else "manual review"
            print(f"OK    {entry['claim'][:52]:52} [{kind}]")
    print(f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
