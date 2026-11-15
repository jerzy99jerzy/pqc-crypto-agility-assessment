# TODO

The single source of truth for what is not done. `docs/METHODOLOGY.md` keeps the
reasoning, this file keeps the state. Which subset of these items makes a
finished product is a different question, answered in `docs/MVP.md`.

Status legend:
- `blocked-external` cannot proceed without a resource that does not exist in
  any build environment used so far (a specific OpenSSL, live tenant, API
  credentials, an owned domain). Not a coding task.
- `ready` can be done in-repo now.
- `decision` needs a human choice, not engineering.

Each open item states an acceptance test, so "done" is not a matter of opinion.
Finished items move to the list at the end with the release they landed in.

---

## Defects and gaps that affect the numbers

### T19 Reconcile the suppression threshold between selection and aggregation
- Status: `ready`
- `pqc-select --min-bucket` and `pqc-collect --min-bucket` are separate
  arguments with the same default, and nothing compares them. The 2026-08-06
  run selected at 5 and aggregated at 1 (`docs/FIELD-RUN.md`); no emitted bucket
  was below 5, so nothing was disclosed, and nothing would have stopped it.
- Decide with it which count the minimum applies to. Aggregation checks
  `hosts_observed`; in the committed education aggregate that is 12, while the
  quantum-vulnerable figure describes the 3 hosts with a certificate.
- Acceptance test: aggregation fails when its threshold differs from the one
  recorded in the selection manifest, unless the aggregate records an explicit
  override with a reason; a test covers both paths, and the chosen count is
  documented in `docs/MECHANISMS.md` section 5.

### T20 Distinguish "no certificate in CT" from "host not collected"
- Status: `ready`
- Nine of twelve education hosts in the field run produced no certificate. The
  aggregate cannot say whether CT holds nothing for them or the run never
  finished asking, and only the first is a finding.
- Acceptance test: the aggregate reports `hosts_not_collected` separately from
  `hosts_without_certificate`, a collection error marks the host as not
  collected, and a test covers a partial run.

### T21 Sensitivity of classification rule order
- Status: `ready`
- First match wins, and on a sector of 8 hosts one colliding domain is 12.5% of
  the denominator, so rule order in `config/classification.yaml` is a free
  parameter that moves published counts.
- Acceptance test: the selection manifest reports, per sector, the count range
  across all orderings of the colliding rules, and the report prints it next to
  the count.

### T25 Catch certificate fingerprints by value
- Status: `ready`
- The structural guard rejects a fingerprint under the `sha256` key and passes
  the same value under any other key or inside a string (probed 2026-11-15). A
  fingerprint resolves to a host through CT.
- Acceptance test: a 64-character hex string and its colon-separated form are
  rejected in any value position; hex strings of other lengths, version strings
  and `file_sha256` of the ranking file in the selection manifest still pass.

### T7 Replace classification heuristics with authoritative registers
- Status: `ready` (data sourcing)
- The `contains:` keyword rules in `config/classification.yaml` are crude by
  admission. For any published figure they should be replaced with registers:
  KNF for supervised financial entities, health registers for healthcare, the
  public-entity register for government.
- Acceptance test: classification driven by an authoritative list per sector,
  the collision counter reporting zero cross-sector collisions on the real
  target set, and the bias note in the selection manifest updated accordingly.

## Blocked on external resources

### T1 Active handshake success path, live execution
- Status: `blocked-external`
- Blocker `[reported]` as of 2026-08-06: no OpenSSL 3.5 client in any
  environment used to build this. The probe refuses to run below 3.5 by design.
- Done in sprint 4: output parser split from the subprocess call and tested
  against synthetic transcripts (`tests/test_handshake.py`), so a real result
  will be read correctly once a 3.5 client exists.
- Acceptance test: `make handshake` against `cloudflare.com` returns a record
  with `pqc_hybrid_negotiated: true` and `openssl_returncode: 0`, and the record
  is committed where `lint-disclosure` can check it.
- Conflict to resolve first: the record names allowlisted hosts by design, and
  `tests/lint_disclosure.py` walks every file under `data/aggregates/` with the
  structural guard, which rejects the `host` key. Committing the record there
  turns the gate red (probed 2026-11-15). Either the lint admits allowlisted
  hosts in that one file, or the record lives elsewhere.
- Fixtures in `tests/fixtures/` are synthetic and labelled as such. They are not
  evidence about any host.

### T2 Declare operator-owned infrastructure under `self`
- Status: `blocked-external`
- Blocker: needs a domain the operator controls and is authorised to test.
- Until then Modality B demonstrates the method against reference
  implementations only, and the README says so in the Modalities section.
- Acceptance test: `config/reference_hosts.yaml` lists at least one `self`
  host, `make handshake` produces a record for it, and it appears in the
  report's active section.
- Privacy note: this repository is public, so naming own infrastructure here
  publishes it. `lint_disclosure` will not block it, because allowlisted hosts
  are permitted by design.

### T3 Censys / Shodan passive enrichment
- Status: `blocked-external`
- Blocker: needs API credentials and a live test. The platform API surfaces
  changed in the year before sprint 1, and a client written from memory would
  put unverified schema assumptions into the repository.
- Acceptance test: a source class with a recorded live response fixture,
  adding served-chain and non-443 TLS dimensions the CT logs do not carry, and
  passing the disclosure guard on its aggregate output.

### T5 Verify Zeek codepoint spelling for 0x11EC on the target sensor build
- Status: `blocked-external`
- Blocker: needs the actual Zeek build in the target environment. Pairs with
  T1: a handshake captured from the operator's own client feeds the sensor.
- Acceptance test: confirm whether the sensor logs `X25519MLKEM768` or
  `unknown-4588`, and prune the unused branch from
  `detection/sigma/zeek_tls_pqc_hybrid_negotiated.yml`.

### T11 Inventory import (CMDB or OT scanner export)
- Status: `blocked-external`
- Blocker: no sample of a real export. A schema designed without one is a guess
  about somebody else's tool, and the mapping is the entire problem.
- Sprint 9 built the seam this plugs into, so the work is a new source class
  rather than a change to the collector.
- Acceptance test: one real export file parses into `CertRecord` values, with
  every unrecognised algorithm resolving to `None` rather than `False` (the
  sprint 6 failure mode, on a new input).

## Ready to do in-repo

### T4 Verify Defender, Sentinel and Resource Graph schema against a live tenant
- Status: `ready` (unblocked by T15)
- The KQL columns are `[inference]` from documentation. Scope:
  `DeviceTvmCertificateInfo`, `DeviceTvmSoftwareInventory`, Application Gateway
  access log field naming, Resource Graph key properties.
- Acceptance test: each query run once with `getschema` (or a sample event) in
  a real tenant and its validation-status row in `detection/README.md` moved
  from `[inference]` to `[measured]`.

### T15 Vendor dev instances: Splunk and Azure Sentinel
- Status: `ready` (was the blocker behind T4 and half of MVP-C)
- Both are obtainable through existing vendor relationships rather than
  purchased or trialled.
- Sequence: write the detection content first, stand both instances up once,
  and validate everything in a single session. Validating piecemeal means
  writing each query twice.
- Acceptance test: every row in `detection/README.md` marked `[inference]` for
  field names moves to `[measured]` with the command that produced it recorded
  (`getschema` for KQL, `| fieldsummary` or a sample event for SPL). Rows that
  cannot be validated stay `[inference]` and say why. The same session records
  what each scheduled query costs at real telemetry volume.

### T16 Sigma to backend compilation
- Status: `ready`
- The rules parse; nothing shows they convert to a deployable query for any
  named target. For the content-pack path this gates release.
- Acceptance test: `sigma convert` produces committed output for at least one
  concrete backend per rule, and CI regenerates it so it cannot drift from the
  rule it came from.

### T18 Offline keystore parsing
- Status: `ready`
- `pqc-keys` reads an export from a managed key service. The other half of the
  at-rest estate lives in keystores on disk: PKCS#12, JKS, and PEM private key
  files next to the certificates the offline source already reads. It needs no
  access to the client's key management.
- Acceptance test: a PKCS#12 bundle yields the same counters as the equivalent
  KMS export, an unparseable or password-protected file is recorded as an error
  rather than dropped, and no alias or friendly name reaches the output.

### T22 `lint_layout` on a checkout without `.git`
- Status: `ready`
- The layout check asks `git check-ignore` which paths are ignored, so it fails
  on a release tarball or a Docker `COPY` without `.git`.
- Acceptance test: `make verify` passes on an extracted sdist with no `.git`,
  and a test simulates the missing repository.

### T23 Complete the field run across every selected sector
- Status: `ready` after T19 and T20
- The 2026-08-06 run produced records for education only, one sector of nine.
- Acceptance test: all selected sectors collected under `tee`, the log kept
  under `runs/`, and the run recorded in `docs/FIELD-RUN.md` with the same
  structure as the first.

### T24 Characterise crt.sh failure modes from a captured log
- Status: `ready` after T23
- The first run's errors were not captured, so they are known to have happened
  and not known to have been rate limiting, timeouts, 5xx or a mixture.
- Acceptance test: `docs/FIELD-RUN.md` gives counts per failure class from a
  captured log, and the retry ladder in `crtsh.py` is checked against them.

### T26 Render the key inventory and the estate cross-check in the report
- Status: `ready`
- `pqc-keys` and `pqc-crosscheck` write guarded counts to `data/aggregates/`,
  and neither report format reads them.
- Acceptance test: both reports render the two outputs when present and state
  "not present" when absent, and a test covers each case.

### T27 Make the architecture block index executable
- Status: `ready`
- The README diagram stayed as drawn in 0.6.0 while sprints 9 to 13 added the
  source seam, the HTML renderer, the cross-check and the key inventory.
  Nothing checks that every module is named in the block index of
  `docs/ARCHITECTURE.md`.
- Acceptance test: `make verify` fails when a module under `ananke/` has no row
  in the block index, or a row names a module that no longer exists.

## Decisions (human, not engineering)

### T13 Portfolio-level licence rationale
- Status: `decision`
- Three repositories, three licences: MIT, Apache-2.0, and AGPL-3.0 plus
  commercial here. Each is defensible alone, and nowhere is it written why they
  differ.
- It needs one paragraph in `LICENSING.md`, or a decision to converge.

---

## Done

- Prose lint in `make verify`: em-dashes, label vocabulary, unused allowlist
  entries; disclosure scan over every tracked document (0.15.4)
- Generated report prints the shared limitations list, checked against the
  README registry; builder docstring states the raw-store read;
  `ananke.__version__` read from the distribution (0.15.2)
- Layout check exemption derived from gitignore in both directions (0.15.1)
- First real field run recorded; competitive review; cadence proposal (0.15.0)
- Layout check: map against the tree, exemptions derived (0.14.1 to 0.14.3)
- IPv6 literals closed in both guards; byte-string values no longer bypass the
  structural walk; ruff and mypy in the gate (T14, 0.14.0)
- At-rest key inventory as a `reported` source, two clocks, no-expiry counter;
  README at-rest claim corrected to four layers (T17, 0.13.0); limitations
  registry in `make verify` (0.13.1)
- Cross-check of a reported estate against its public CT footprint (T12,
  0.12.0); SPL detection pack with a structural discipline lint (0.12.0)
- Configurable milestone, decision layer in the aggregate, HTML report through
  the same guard (0.11.0); quasi-identifier rule for the chart (A7, 0.11.1)
- Single `ananke` namespace, `SECURITY.md`, threat model, architecture document,
  `pqc-fixture` with adversarial estates (0.10.0); sector label and SAN length
  fixes (0.10.2)
- Source seam: `CrtShSource` and `LocalPemSource`, `reported` provenance,
  suppression relaxed only for first-party estates (0.9.0)
- Disclosure guard boundary defect closed; filename allowlist derived from
  `git ls-files` (0.8.0)
- Dual licence, AGPL-3.0-only or commercial; tags v0.5.0 to v0.7.0 remain MIT
  (T10, after 0.7.0)
- NSS 3.118 and LibreSSL thresholds from primary sources; sourced-negative path
  (T6, 0.7.0)
- Correctness review of the 0.5.0 tree: F1, F2, F3 (0.6.0)
- Packaging with console scripts and a coverage floor in CI (T8, T9, sprint 5);
  handshake parser tested against synthetic transcripts (sprint 4)
- Passive CT collection, HNDL scoring, Sigma and KQL pack, selection manifest,
  executable disclosure guard, report generator (sprints 1 to 3)
