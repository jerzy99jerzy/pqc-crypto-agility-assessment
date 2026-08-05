# TODO

Compiled from the open items tracked across sprints. This is the single source
of truth for what is not done; `docs/METHODOLOGY.md` keeps the reasoning, this
file keeps the state.

Status legend:
- `blocked-external` cannot proceed without a resource that does not exist in
  any build environment used so far (a specific OpenSSL, live tenant, API
  credentials, an owned domain). Not a coding task.
- `ready` can be done in-repo now.
- `done` shipped; kept here with the sprint it landed in for traceability.
- `decision` needs a human choice, not engineering.

Each open item states an acceptance test, so "done" is not a matter of opinion.
Which subset of them constitutes a finished product is a different question and
is answered in `docs/MVP.md`, not here.

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
- Status: `ready` (unblocked by T15: dev tenant available through a vendor relationship)
- Was blocked on tenant access; that is resolved. The KQL columns are `[inference]` from
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
- Status: `done`, completed sprint 7
- GnuTLS 3.8.8 and wolfSSL 5.8.0 set with `provenance: measured` in sprint 5.
- NSS set to 3.118 (sprint 7): standardised ML-KEM TLS groups added and made
  default there; the pre-standard Kyber draft was disabled in 3.116, so 3.118 is
  a clean cutover. Primary sources in the config.
- LibreSSL encoded as a sourced negative (sprint 7): a 2025 survey found no PQC
  in any released version through 3.9, so `pqc_absent_through: "3.9"` resolves
  <= 3.9 to a measured `not_capable` and newer releases to `unknown`.

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
  scripts run, 82 tests pass (147 as of sprint 8).

### T9 Coverage measurement in CI
- Status: `done`, sprint 5
- `pytest-cov` configured in `pyproject.toml`, `make coverage`, `fail_under=70` (raised from 65 in sprint 6)
  enforced in CI. The subprocess branch of the handshake carries
  `# pragma: no cover` with a reason; the gap to 100% is argparse `main()`
  wrappers exercised through their callees, not hidden logic. Current total
  ~75% (sprint 8).

---

## Decisions (human, not engineering)

### T12 Cross-check a reported estate against the passive layer
- Status: `ready`
- `docs/THREAT-MODEL.md` A3 has no control on the input, only on the label: an
  operator's dump cannot be shown complete from the dump. The available check is
  to run the passive layer against the same operator's public estate and compare.
  A host present in CT and absent from the dump is a finding, not an error.
- This is the difference between an assessment and a transcription, and it is
  the thing that makes a first-party engagement worth paying for.
- Acceptance test: a synthetic pair where the offline dump omits a host that CT
  shows, and the comparison reports it without either store contaminating the
  other or the aggregate naming the host.

---

### T13 Portfolio-level licence rationale
- Status: `decision`
- Three repositories, three licences: MIT, Apache-2.0, and AGPL-3.0 plus
  commercial here. Each is defensible alone; nowhere is it written why they
  differ, and the question will be asked by anyone evaluating the portfolio as a
  whole rather than one repository.
- Not an engineering item. It needs one paragraph, in `LICENSING.md`, or a
  decision to converge.

---

### T18 Offline keystore parsing
- Status: `ready`
- `pqc-keys` reads an export from a managed key service. The other half of the
  at-rest estate lives in keystores on disk: PKCS#12, JKS, and PEM private key
  files next to the certificates the offline source already reads.
- Worth doing because it needs no access to the client's key management at all,
  which is the same property that makes the offline certificate path usable in
  a first meeting.
- Acceptance test: a PKCS#12 bundle yields the same counters as the equivalent
  KMS export, an unparseable or password-protected file is recorded as an error
  rather than dropped, and no alias or friendly name reaches the output.

---

### T16 Sigma to backend compilation
- Status: `ready`
- The rules parse; nothing shows they convert to a deployable query for any
  named target. A buyer wants to paste a query, not an intermediate
  representation, so for the content-pack path this is a gating item rather
  than polish.
- Acceptance test: `sigma convert` produces committed output for at least one
  concrete backend per rule, and the committed output is regenerated in CI so
  it cannot drift from the rule it came from.

---

### T15 Vendor dev instances: Splunk and Azure Sentinel
- Status: `ready` (was the blocker behind T4 and half of MVP-C)
- Both are obtainable through existing vendor relationships rather than
  purchased or trialled, which removes the access problem that made MVP-C
  inexpressible in sprints. Recorded here because the backlog previously
  treated it as external and immovable, and that is no longer true.
- Sequence matters: write the detection content first, stand both instances up
  once, and validate everything in a single session. Validating piecemeal means
  writing each query twice.
- Acceptance test: every row in `detection/README.md` marked `[inference]` for
  field names moves to `[measured]` with the command that produced it recorded
  (`getschema` for KQL, a `| fieldsummary` or sample event for SPL). Rows that
  cannot be validated stay `[inference]` and say why.
- Second-order value beyond field validation: a live tenant is the only way to
  find out whether these queries are affordable at real telemetry volume. A
  correct query that costs a fortune to schedule is not deployable content.

---

### T14 IPv6 literals bypass the disclosure guard
- Status: `done` (sprint 14)
- Found in the threat-model v2.0 review. `HOSTNAME_RE` and `IPV4_RE` cover
  named hosts and dotted-quad addresses; a bare or bracketed IPv6 literal
  (`2a00:1450:401b:80c::200e`) matches neither and passes both guards.
- Low exposure today (a certificate SAN is rarely an IPv6 literal, and the
  reference estate has none) but it is a real hole in the structural guard, so
  it is tracked rather than left implicit.
- Acceptance test: an IPv6 literal in a record value raises `DisclosureViolation`;
  a version-like or time-like colon string (`12:34:56`) does not.

---

### T11 Inventory import (CMDB / OT scanner export)
- Status: `blocked-external`
- Blocker: no sample of a real export. A CSV or JSON schema designed without one
  is a guess about somebody else's tool, and the mapping is the entire problem.
- Sprint 9 built the seam this plugs into, so the work is a new source class
  rather than a change to the collector.
- Acceptance test: one real export file from a client or pilot parses into
  `CertRecord` values, with every unrecognised algorithm resolving to `None`
  rather than `False` (the sprint 6 failure mode, on a new input).

---

### T10 License
- Status: `done`, decided after sprint 7
- Resolved to dual licensing: AGPL-3.0-only for community use, commercial
  license from the author to waive copyleft. AGPL section 13 is the operative
  clause, since the plausible commercial deployment is a network service. See
  `LICENSING.md`.
- Note: tags v0.5.0 through v0.7.0 were published under MIT and that grant is
  not retroactively revocable. Relicensing binds later releases only.

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
- Correctness review of the shipped tree: tri-state algorithm identification (unknown is not post-quantum), version-truncation fix, IPv4 detection in the disclosure guard, `docs/MECHANISMS.md`, coverage floor 65 -> 70 (sprint 6)
- NSS (3.118) and LibreSSL capability thresholds verified against primary sources; sourced-negative resolver path (`pqc_absent_through`) distinguishing a confirmed absence from unknown (sprint 7)
- IPv6 literals closed in both guards via candidate-plus-validation rather than regex alone; byte-string values no longer bypass the structural walk; ruff and mypy in the gate (T14, sprint 14)
- At-rest key inventory as a `reported` source: wrapping and signing keys counted on separate clocks, symmetric counted and excluded from scope, no-expiry surfaced as the agility finding; README's at-rest claim corrected to four layers (T17, sprint 13)
- Cross-check of a reported estate against its public CT footprint: asymmetric by design (publicly logged and undeclared is a finding, declared and not publicly logged is not), counts only, blind spot stated rather than implied (T12, sprint 12)
- SPL detection pack alongside KQL, with a structural discipline lint in `make verify` (sprint 12)
- Portfolio consistency: single `ananke` package namespace (five generic top-level packages removed), uppercase documentation filenames, `SECURITY.md`, `docs/THREAT-MODEL.md`, `docs/ARCHITECTURE.md` with block index, `pqc-fixture` synthetic estates including two adversarial worlds, prose-only infrastructure allowlist (sprint 10)
- Source seam: `CrtShSource` and `LocalPemSource` behind one interface; aggregate reports the regime instead of constants; `reported` provenance for operator-supplied sets; suppression relaxed only for first-party estates (sprint 9)
- Disclosure guard boundary defect (host identity adjacent to `_` matched nothing and passed both guards); filename allowlist derived from `git ls-files` for the prose scan, strict guard restored to zero filename exemptions (sprint 8)
