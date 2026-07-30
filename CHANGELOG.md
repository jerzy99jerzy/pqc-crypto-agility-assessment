# Changelog

All notable changes to this project are documented here.
Format based on Keep a Changelog; this project uses semantic versioning.

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
