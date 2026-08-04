# Changelog

All notable changes to this project are documented here.
Format based on Keep a Changelog; this project uses semantic versioning.

## [0.8.0] - 2026-08-04

Correctness sprint against the disclosure guard, the module that enforces the
scope statement. One defect class, one self-inflicted regression, and the end
of the hand-maintained filename allowlist that produced both.

### Fixed
- **Host identity adjacent to an underscore passed both guards.** `HOSTNAME_RE`
  and `IPV4_RE` were anchored on `\b`. Underscore is a word character, so no
  boundary exists between `_` and a letter and no match could begin there:
  `acme_bank.pl`, `cn=corp_bank.pl` and `host_10.0.0.1` produced no regex match
  at all and were written out silently. Boundaries are now explicit, treating
  `_` as a delimiter and catching a host glued to a trailing suffix
  (`bank.pl_backup`) as well. Present since the guard shipped in sprint 2.
- **The strict guard had acquired filename exemptions it was documented never
  to have.** The sprint 7 CI fix added repository document names to
  `ALLOWED_TOKENS` so the prose lint would stop failing on `LICENSING.md`; that
  set is shared with `assert_no_host_identifiers`, so `{"source":
  "mechanisms.md"}` became publishable structured output. The two allowlists
  are now separated by intent.
- **Eight of twenty-four `ALLOWED_TOKENS` entries were unreachable.** Every one
  contained an underscore, which the regex could never yield as a whole token
  (`hndl_score.py` tokenises as `score.py`). Removed.

### Changed
- **Repository filenames are derived, not listed.** `_repo_file_tokens()` reads
  the tracked file list via `git ls-files`, falling back to a scoped filesystem
  walk for a source tarball with no `.git`, and fails closed to an empty set.
  Names under `data/` are never eligible, since a filename there can be
  host-derived. Admitted in `scan_text` only, behind an explicit
  `repo_files=True` argument that the structural guard never passes.
- `ALLOWED_TOKENS` reduced to the five tokens that are genuinely not filenames
  or are emitted by the writers.

### Added
- `tests/test_sprint8.py`: nine cases failing against 0.7.0, covering both
  boundary defects in both patterns, the strict/prose split, the git and
  fallback derivation paths, exclusion of the raw store, fail-closed behaviour,
  and a build-breaking check that no `ALLOWED_TOKENS` entry is unreachable.
- Version-string cases (`3.5.0.2024`, `1.1.1w`) pinning the looser boundary
  against false positives in the other direction.

## [0.7.0] - 2026-08-03

Capability sprint. Closes the last two `null` entries in the capability
configuration with primary-sourced values, and adds a resolver mechanism to
express a *sourced negative* — a confirmed absence — as distinct from unknown.

### Added
- **NSS capability threshold: 3.118** (`measured`). The standardised ML-KEM TLS
  groups landed in NSS 3.118 (`mlkem768x25519` made default, `secp256r1mlkem768`
  and `secp384r1mlkem1024` added). The pre-standard Kyber draft was disabled in
  3.116 and 3.117 added no TLS ML-KEM, so 3.118 is a clean cutover, not a
  default-flip over an earlier non-default window. Primary sources in the config.
- **LibreSSL as a sourced negative.** A 2025 survey found no PQC in any released
  LibreSSL version through 3.9. New config field `pqc_absent_through` records the
  verified ceiling: a version at or below it resolves to a measured `not_capable`;
  a newer release resolves `unknown` rather than being assumed incapable on a
  version the source never examined.
- `tests/test_sprint7.py`: NSS threshold cases, LibreSSL sourced-negative in both
  directions, and resolver precedence (a positive threshold wins over
  `pqc_absent_through`).

### Changed
- `resolve()` gains the `pqc_absent_through` branch. A positive
  `pqc_hybrid_kex_from` still takes precedence; the negative path is consulted
  only when no positive cutover exists.
- Capability config bumped to 1.1 (2026-08-03).
- Docs realigned: methodology, mechanisms, README, TODO no longer describe NSS
  and LibreSSL as `null -> unknown`.

## [0.6.0] - 2026-08-02

Correctness sprint. Three defects found by review of the 0.5.0 tree, each of
which produced a plausible wrong number rather than a crash - the failure mode
that matters most for a measurement tool. All three now have regression tests
that fail against the 0.5.0 code.

### Fixed
- **Unidentified algorithms no longer report as post-quantum.** `certparse`
  returned `quantum_vulnerable=False` for any key or signature OID it could not
  identify, which downstream is indistinguishable from a measured PQC
  algorithm: the aggregator counted it as a PQC indicator and the
  vulnerable-key count shrank. The flags are now tri-state
  (`True` / `False` / `None`), so unknown stays unknown, prices as 0.5 in
  scoring with provenance `unknown`, and appears as its own bucket in the
  aggregate. Silent inflation of PQC adoption in the direction that flatters
  the estate.
- **Truncated version strings resolve correctly.** `compare_versions("3.5",
  "3.5.0")` returned -1, so an inventory export that truncates a trailing zero
  resolved an upgraded host as `not_capable`. Trailing numeric zeros are now
  insignificant; a non-zero tail still decides. The pre-release ordering
  limitation is documented in the function rather than half-fixed.
- **The disclosure guard now sees IPv4 literals.** `HOSTNAME_RE` requires an
  alphabetic final label, so a dotted quad passed through the structural guard
  and could reach a committed aggregate. IPv4 detection added to both the
  structural guard and the prose scan, with octet range-checking so version
  strings are not false-positived.

### Added
- `docs/mechanisms.md`: how each mechanism works, for readers who want the
  implementation rather than the thesis or the epistemics.
- `tests/test_sprint6.py`: regression guards for the three fixes, plus coverage
  of report rendering and store-level scoring.

### Changed
- Coverage floor raised 65 -> 70 (measured: 73.85%, 108 tests). The floor is a
  ratchet; the remaining margin is headroom against refactors, not slack.
- Removed the unused `CLASSICAL_VULNERABLE` constant from `certparse`.

## [0.5.0] - 2026-07-30

First tagged release. Repeatable PQC crypto-agility assessment: passive
discovery, HNDL scoring, detection content, reporting, with coverage and
disclosure gates enforced in CI.

### Added
- Passive certificate collection over public Certificate Transparency
  (collectors/crtsh.py, passive_cert.py, certparse.py), local raw store
  (collectors/store.py), public-ranking target selection (collectors/select_targets.py).
- Sector-level HNDL exposure scoring with a configurable weights/horizon model
  and a config validator (scoring/hndl_score.py, `pqc-score --validate-config`).
- PQC capability resolution from a software inventory export
  (inventory/pqc_capability.py).
- Detection pack: Sigma (Schannel TLS negotiation, Zeek TLS classical-only,
  Zeek TLS PQC-hybrid, Zeek x509 vulnerable-key-beyond-2030) and KQL/Sentinel
  (Key Vault key inventory, MDE certificate inventory beyond 2030, MDE crypto
  library capability, App Gateway TLS migration burndown).
- Active PQC-hybrid handshake probe, allowlisted hosts only, OpenSSL >= 3.5
  (active/handshake_demo.py).
- Report rendering from committed aggregates (reporting/build_report.py).
- Disclosure lint scanning committed artefacts for host identifiers
  (collectors/disclosure.py, tests/lint_disclosure.py).
- Provenance discipline (measured / inference / assumption / speculation) across
  outputs and docs.
- Packaging (pyproject.toml), Make targets, and a `make verify` gate:
  coverage floor, Sigma validation, scoring-config validation, disclosure lint.

### Notes
- Sector aggregation only; no entity is named alongside a vulnerability label.
- Third-party estate read from public data only; active probing limited to own
  and reference infrastructure.

[0.5.0]: https://github.com/jerzy99jerzy/pqc-crypto-agility-assessment/releases/tag/v0.5.0

[0.6.0]: https://github.com/jerzy99jerzy/pqc-crypto-agility-assessment/releases/tag/v0.6.0

[0.7.0]: https://github.com/jerzy99jerzy/pqc-crypto-agility-assessment/releases/tag/v0.7.0
