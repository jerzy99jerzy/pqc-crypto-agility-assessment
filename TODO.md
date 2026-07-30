# TODO

Compiled from the open items tracked across sprints. This is the single source
of truth for what is not done; `docs/methodology.md` keeps the reasoning, this
file keeps the state.

Status legend:
- `blocked-external` cannot proceed without a resource that does not exist in
  any build environment used so far (a specific OpenSSL, live tenant, API
  credentials, an owned domain). Not a coding task.
- `ready` can be done in-repo now.
- `done` shipped; kept here with the sprint it landed in for traceability.
- `decision` needs a human choice, not engineering.

Each open item states an acceptance test, so "done" is not a matter of opinion.

---

## Blocked on external resources

### T1 Active handshake success path, live execution
- Status: `blocked-external`
- Blocker: no OpenSSL >= 3.5 client in any environment used to build this. The
  probe refuses to run below 3.5 by design.
- Done in sprint 4: output parser split from the subprocess call and tested
  against synthetic transcripts (`tests/test_handshake.py`), so a real result
  will be read correctly once a 3.5 client exists.
- Acceptance: `make handshake` against `cloudflare.com` returns a record with
  `pqc_hybrid_negotiated: true` and `openssl_returncode: 0`, committed to
  `data/aggregates/handshake_demo.json`.
- Note: fixtures in `tests/fixtures/` are synthetic and labelled as such. They
  are not evidence about any host.

### T2 Declare operator-owned infrastructure under `self`
- Status: `blocked-external`
- Blocker: needs an HBCC domain the operator controls and is authorised to test.
- Impact: until then Modality B demonstrates the method against reference
  implementations only, so the README claim "PQC-readiness demonstrated on own
  infrastructure" is not yet backed.
- Acceptance: `config/reference_hosts.yaml` lists at least one `self` host,
  `make handshake` produces a record for it, and it appears in the report's
  active section.
- Privacy note: naming own infrastructure in a public repo is a deliberate
  exposure. `lint_disclosure` will not block it because allowlisted hosts are
  intentionally permitted. Decide before pushing to a public remote.

### T3 Censys / Shodan passive enrichment
- Status: `blocked-external`
- Blocker: needs API credentials and a live test. The platform API surfaces
  changed within the last year; writing a client from memory would put
  unverified schema assumptions into the repo, which is the exact failure the
  project exists to avoid.
- Acceptance: a `collectors/censys.py` with a recorded live response fixture,
  adding served-chain and non-443 TLS dimensions the CT logs do not carry, and
  passing the disclosure guard on its aggregate output.

### T4 Verify Defender / Sentinel / ARG schema against a live tenant
- Status: `blocked-external`
- Blocker: no tenant available here. The KQL columns are `[inference]` from
  documentation.
- Scope: `DeviceTvmCertificateInfo`, `DeviceTvmSoftwareInventory`,
  Application Gateway access log field naming, Resource Graph key properties.
- Acceptance: each query run once with `getschema` (or a sample event) in a
  real tenant and its validation-status row in `detection/README.md` flipped
  from `[inference]` to `[measured]`.

### T5 Verify Zeek codepoint spelling for 0x11EC on the target sensor build
- Status: `blocked-external`
- Blocker: needs the actual Zeek build in the target environment.
- Acceptance: confirm whether the sensor logs `X25519MLKEM768` or
  `unknown-4588`, and prune the unused branch from
  `detection/sigma/zeek_tls_pqc_hybrid_negotiated.yml`.

---

## Ready to do in-repo

### T6 Capability thresholds for GnuTLS, NSS, wolfSSL, LibreSSL
- Status: `done` (partial), sprint 5
- GnuTLS 3.8.8 and wolfSSL 5.8.0 set with `provenance: measured` and reference
  URLs. NSS and LibreSSL left `null` -> `unknown`: NSS has shipped hybrid PQ but
  the exact release cutover was not confirmed against a primary source, and
  guessing it would be the failure this project exists to avoid.
- Remaining: verify NSS and LibreSSL cutover versions from their release notes.

### T7 Replace classification heuristics with authoritative registers
- Status: `ready` (data sourcing) but see the decision note
- The `contains:` keyword rules in `config/classification.yaml` are crude by
  admission. For any published figure they should be replaced with registers:
  KNF for supervised financial entities, health registers for healthcare, the
  public-entity register for government.
- Acceptance: classification driven by an authoritative list per sector, the
  collision counter reporting zero cross-sector collisions on the real target
  set, and the bias note in the selection manifest updated accordingly.

### T8 Package the project (pyproject.toml)
- Status: `done`, sprint 5
- `pyproject.toml` with flat package layout and six `pqc-*` console scripts.
  `pip install -e ".[dev]"` via `make install`. Test path handling centralised
  in `tests/conftest.py`; the per-file `sys.path.insert` boilerplate is gone
  from the test suite. Module-level fallbacks for direct-script execution are
  kept deliberately, since the collectors can still be run by path.
- Verified: imports resolve from an unrelated working directory, console
  scripts run, 82 tests pass.

### T9 Coverage measurement in CI
- Status: `done`, sprint 5
- `pytest-cov` configured in `pyproject.toml`, `make coverage`, `fail_under=65`
  enforced in CI. The subprocess branch of the handshake carries
  `# pragma: no cover` with a reason; the gap to 100% is argparse `main()`
  wrappers exercised through their callees, not hidden logic. Current total
  ~69%.

---

## Decisions (human, not engineering)

### T10 License
- Status: `decision`
- Sprint 4 ships an MIT `LICENSE` as a working default. If this is a portfolio
  artefact meant to be read but not reused, or if a copyleft or source-available
  license fits better, change it. It is one file.

### T11 Track A vs Track B framing of this artefact
- Status: `decision`
- Out of scope for the code, in scope for why it exists. This repo reads as
  Track A evidence: field-facing, method-and-provenance over a headline finding.
  Worth being deliberate about whether it is presented that way.

---

## Done

- Passive CT collection, atomic idempotent store, X.509 PQC OID parsing (sprint 1)
- HNDL scoring, config-driven, no hardcoded constants (sprint 1)
- Sigma + KQL detection pack with an honest validation-status table (sprint 1)
- Selection manifest: hashed ranking, hashed ruleset, collision detection (sprint 2)
- Exposure-cap saturation fix, derived cap + config validator (sprint 2)
- Disclosure guard as executable code + external lint + CI (sprint 2)
- Report generator that cannot read raw host data (sprint 2)
- Collection-path tests: retry ladder, limiter, failure modes (sprint 3)
- Endpoint capability resolver with real semantic version comparison (sprint 3)
- Handshake output parser split out and tested via synthetic transcripts (sprint 4)
- Verified capability thresholds (GnuTLS, wolfSSL); packaging + console scripts; coverage floor in CI (sprint 5)
