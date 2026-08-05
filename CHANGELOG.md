# Changelog

All notable changes to this project are documented here.
Format based on Keep a Changelog; this project uses semantic versioning.

## [0.14.0] - 2026-08-05

Every defect detected but not yet fixed, closed in one sprint. Two of them were
real holes in the structural guard and one of those was found by a type checker
that had not been running.

### Security
- **T14: IPv6 literals passed both guards.** Neither host pattern matches a
  colon-separated address, so a bare or bracketed literal walked through
  untouched. Closed with candidate nomination plus `ipaddress` validation rather
  than regex alone: an expression loose enough to catch every valid form also
  catches clock times, MAC addresses and C++ scope resolution, while one tight
  enough to avoid them misses compressed forms. Validation is exact by
  construction - `12:34:56` is rejected because it is not an address, not
  because a rule was written about times. `::` and `::1` are exempt, because
  they identify nobody and flagging them would train people to disable the
  guard.
- **Byte-string values bypassed the structural walk.** `assert_no_host_identifiers`
  inspected `str` and recursed into containers, so a `bytes` value was ignored
  entirely. `NameAttribute.value` is `str | bytes` and `cryptography` returns
  bytes for encodings it declines to decode, so a certificate subject encoded
  that way carried host identity into the aggregate. Found by mypy on a return
  type that did not match its declaration, on the first run after the type
  checker was added. Fixed on both sides independently: the parser decodes, and
  the guard treats byte strings as strings, so neither fix depends on the other.

### Added
- `ruff` and `mypy` in the dev dependencies and in `make verify`, converging
  with `cve-digest`. 65 lint findings and 12 type findings resolved; the mypy
  configuration is deliberately not strict, because the value here is catching a
  `None` or a `bytes` flowing into a branch that assumes otherwise, which the
  tri-state convention makes the most likely defect shape in this codebase.
- `ENGINEERING.md`: the portable engineering standard distilled from this
  repository and its siblings, with every rule traced to the defect that
  produced it.
- `docs/DECISIONS.md`: rejected options with their reasoning and, for each, the
  condition that should reopen it. A decision without a revisit condition
  becomes a rule nobody remembers the reason for.
- `tests/test_sprint14.py`: 21 cases covering the IPv6 guard in both directions,
  the colon-bearing text that must not be flagged, and a test asserting CI still
  calls the single gate.

### Fixed
- **CI ran weaker than the local gate.** The workflow listed checks
  individually, so `lint-spl` and `lint-limitations` were local-only for a day
  while the Makefile comment claimed "everything CI runs". CI now calls
  `make verify`. The same class as the stale README claim in 0.13.1, in the
  build system rather than the documentation.
- CI gains a Python matrix (3.12 and 3.14, the second being the version
  development actually happens on), an interpreter-free hygiene job rejecting
  tracked patch files and absolute developer paths, and a job asserting a
  pushed tag matches the declared version - which would have caught both of the
  tag-artefact mismatches this project shipped.

## [0.13.1] - 2026-08-05

### Added
- **`make lint-limitations`**, wired into `verify`. Checks the README's "What
  this assessment will not tell you" section against the tree, bidirectionally:
  every bullet must be registered in `tests/lint_limitations.py` with probes,
  and every registry entry must still have its bullet. `must_exist` probes
  assert the code property that makes a claim true is present; `must_not_exist`
  probes assert a denied capability has not appeared. Verified against all three
  drift modes, including the historical one - the at-rest claim that went stale
  when `pqc-keys`-style enumeration existed while the README denied it.
- `CONTRIBUTING.md`: the principle behind the check. A claim the repository
  makes about itself and a reader relies on should be executable, because a
  sentence drifts silently and a test drifts loudly.

### Why this is its own release
The gap it closes was found by a user's question, not by review, and it is the
one class of defect three code reviews structurally could not catch: divergence
between the code and the repository's description of itself. The check now fails
the build on it.

## [0.13.0] - 2026-08-05

Cryptography at rest, and the correction of a claim this repository had been
making about itself.

### Added
- **`pqc-keys` (T17).** Summarises an operator-supplied key management export
  (Azure Resource Graph, `aws kms describe-key`, GCP KMS list) into sector
  counts. The engagement needs no credentials into the client's key
  management: they produce the export, so provenance is `reported` for the
  same reason the offline certificate estate is.

  Two design points carry it. **Signing and wrapping keys are counted
  separately**, because a wrapping key carries harvest-now-decrypt-later
  exposure while a signing key carries forgery-after-Q-day exposure on a longer
  and differently regulated horizon, and a combined figure means nothing for
  either. **Symmetric keys are counted and excluded from migration scope**
  rather than omitted, so the report can say the AES layer is fine instead of
  leaving a client to assume the worst.

  The strongest at-rest finding available needs no new observation and is
  surfaced as its own counter: a key with no expiry is a key nobody planned to
  rotate, which makes it a key nobody planned to migrate. That is a statement
  about crypto-agility rather than cryptography, which is the thesis of the
  project.
- `tests/test_sprint13.py`: 35 cases, including tri-state classification on a
  third input path, the purpose split, epoch and ISO expiry, absent versus
  unknown rotation policy, and that no key identifier or vault name reaches the
  written output.

### Changed
- **`README.md` corrected.** The flat claim that the assessment "does not see
  cryptography at rest" was false against the repository's own contents
  (`detection/kql/arg_keyvault_key_inventory.kql` has enumerated stored
  asymmetric keys since sprint 4) and unhelpful to a reader, because at rest is
  four layers and only two are post-quantum problems. Now stated as four:
  bulk AES is out of migration scope entirely and needs no budget; the
  asymmetric wrapping layer is the real exposure and is countable; signing keys
  run on a different clock; application-layer cryptography is invisible and the
  project does not pretend otherwise. Keys held outside any managed service are
  named as the category no modality here can reach, and usually the worst part
  of an estate.

## [0.12.0] - 2026-08-05

The control on the client who supplies a convenient dump, and a second
detection target.

### Added
- **`pqc-crosscheck` (T12).** Compares an operator-supplied estate against the
  same operator's public Certificate Transparency footprint. This is the only
  available control on adversary A3: nothing inside a directory of certificates
  can show the directory is the estate, but the operator can be looked for in a
  record they do not curate.

  The asymmetry is the design. Publicly logged and absent from the dump is a
  finding. Declared and not publicly logged is *not*: internal PKI never
  reaches a public log, and counting it as a discrepancy would produce noise in
  proportion to how well the internal CA is run. The blind spot - a host both
  internally issued and omitted - is stated in the output rather than implied.

  Output is counts. Host names are compared in memory and never written: the
  result is "two publicly logged certificates were not in the supplied set",
  never which two. The operator reproduces the list locally; a report that
  travels does not carry it. Written through the guard anyway.
- **SPL detection pack** (`detection/spl/`), four searches alongside the KQL
  set: key-exchange inventory with numerator and denominator from one filter,
  certificates with no renewal scheduled before the milestone, crypto-library
  capability, and a burndown trend using `tstats` where a data model exists.
  Version comparison uses a zero-padded numeric key rather than string
  comparison, because `"3.5"` sorts below `"3.10"` and that exact defect
  shipped once in the pipeline (F2, sprint 6).
- **`make spl-check`**, wired into `verify`. Deliberately not a parser: there is
  no offline SPL parser worth trusting, and half of one would pass broken
  searches while implying they were checked. It verifies discipline instead -
  every search declares its question, source assumption and validation status,
  the milestone is a macro rather than a retyped date, and no search filters on
  `="true"` in a way that drops the `unknown` state.
- `tests/test_sprint12.py`: 16 cases, pinning the asymmetry from both
  directions, normalisation against false discrepancies (a CT wildcard against
  the declared apex), count-only output, and the lint's own rules.

### Changed
- **T4 is no longer blocked.** Dev instances of both Splunk and Azure Sentinel
  are obtainable through existing vendor relationships (T15), which removes the
  access problem that made MVP-C inexpressible in sprints. `docs/MVP.md` revised
  accordingly: the path that looked furthest from ready is the one whose
  blockers dissolved first.
- T16 recorded: Sigma rules parse but no backend compilation output is
  committed. Gating for the content-pack path.

### Fixed
- The SPL lint flagged this repository's own comment warning against the
  dropped-`unknown` anti-pattern, because content checks ran over the whole
  file. Scoped to the search body, which is how a linter avoids teaching people
  to stop documenting what it checks for.

## [0.11.1] - 2026-08-05

Threat-model review (v2.0) and the one code fix it produced.

### Security
- **A7, re-identification through quasi-identifiers.** The HTML horizon chart
  embedded per-certificate validity date pairs on the assumption that dates
  carry no identity. Measured on the reference estate, every `(not_before,
  not_after)` pair is unique, and Certificate Transparency is searchable by
  those fields, so the "anonymous" segments were a de-anonymisation oracle for
  any host in CT. The chart now renders for first-party estates only, where the
  hosts belong to the commissioner; a third-party report gets counts and bands,
  never per-certificate segments. Pinned by a test.

### Documentation
- `docs/THREAT-MODEL.md` to version 2.0: every documented residual risk
  re-probed against the code. Two corrected in the project's favour (punycode
  IDNs, URLs-with-credentials, e-mail local parts and uppercase hosts are all
  caught, not open as previously stated); the boundary map gains B5 (command
  line) and B6 (the chart's raw-store read); A7 added; A8 records that the patch
  delivery chain itself failed twice this week and gets a `MANIFEST.sha256`
  control from sprint 12.

### Known issues
- T14: IPv6 literals bypass the structural guard. Found in this review, tracked
  with an acceptance test, low exposure today.

## [0.11.0] - 2026-08-05

The report becomes a decision document. Sprint 11 in three moves: the
milestone becomes configuration, the aggregate grows the split a plan is built
from, and the report renders to HTML through the same disclosure gate as
markdown.

### Added
- **Configurable milestone.** `ananke/config.py` reads `milestone.date` from
  `weights.yaml` (default 2030-12-31, the EU coordinated roadmap date, kept
  with its provenance). `--milestone` on `pqc-collect`; sources stamp each
  record with the milestone it was parsed under.
- **Decision layer in the aggregate**, per sector, counts only:
  `self_resolving_via_rotation` vs `intervention_required` (recomputed from
  `not_after` against the aggregation-time milestone, never read from the
  stored boolean, so one store reclassifies under any milestone without
  recollecting), expiry-year distribution of the intervention class, rotation
  bands, `rotation_stats` (median/min/max validity and rotations-before-
  milestone), and issuer distribution.
- **`pqc-report --format html`.** One file, no network requests, designed dark
  palette via `prefers-color-scheme`, print forces light. Interactive validity
  horizon: every certificate as a date segment against a movable milestone
  rule. Every interpolated value is escaped at the point of use; the chart
  payload embeds date pairs only and the renderer drops any other field.
- `tests/test_sprint11.py`: 13 cases covering the milestone swing, counter
  emission, the issuer near-miss, escaping, and the embedded-data scan.

### Changed
- `valid_beyond_2030_milestone` renamed to `valid_beyond_milestone`, with the
  old key still read everywhere (stores and scoring subjects from earlier
  versions keep working). Records now carry `milestone_date`.
- The report guard understands HTML: `<script>`/`<style>` bodies are stripped
  before the prose scan - JavaScript is full of host-shaped tokens
  (`ms.value`, `Date.UTC`) that are code, not content - and every string
  literal inside script blocks is then walked separately, so a host
  identifier smuggled into embedded data still fails while the code around it
  does not. Code is repository-reviewed; data changes per engagement, which
  is why data gets the stricter path.

### Security
- **Issuer distribution near-miss, caught during development.** On a
  self-signed certificate the issuer IS the subject, so counting issuer CNs
  would have walked host identity straight into committed aggregates - the
  guard's A1 class, introduced and stopped inside one sprint by the sprint 2
  suppression test. Shipped version counts `issuer_o` only, drops any
  host-shaped value, and buckets the rest as self-signed. Pinned by two
  regression tests.

## [0.10.2] - 2026-08-05

*Released as part of v0.11.0: the fixes below were cut on the same day and the
patch was folded into the minor release rather than tagged separately.*

Security review of the sprint 9-10 surface, done by probing rather than
reading. Three findings, all fixed, all pinned with regression tests. The
threat model gains an adversary class (A6) and records what was probed and
held: path traversal through a subject CN cannot escape the store, and a 50 MB
junk file parses in milliseconds with an error recorded.

### Security
- **S1: the sector label could publish an organisation name.** The label given
  with `--sector` becomes a dictionary key in the committed aggregate, and the
  disclosure guard walks values, never keys, so `--sector "acme-bank.pl
  production"` shipped a name into the one artefact that promises to contain
  none. Labels are now shape-validated at the source: a plain categorical
  token, lowercase, no dots - the dot being exactly what makes a string
  host-shaped. Aggregation re-checks every key independently, so a future
  source that forgets the first check fails at the second.
- **S2: the same channel carried markup.** A label containing `<script>` or
  markdown table syntax was stored verbatim: cross-site scripting waiting for
  the HTML renderer, table injection already reachable in the markdown one.
  Refused by the same shape validation.
- **S3: one crafted certificate stopped the whole run.** A subject CN is capped
  at 64 bytes by X.509, but a SAN dNSName is not, and host identity falls back
  to SAN, so a 250-character SAN crashed the store write with `OSError: File
  name too long`. Store keys are now capped at 120 characters with a SHA-256
  suffix that preserves uniqueness; a hostile estate cannot stop an assessment
  with one long name.

### Added
- `docs/THREAT-MODEL.md` A6: a hostile estate that attacks the run itself,
  with the empirical results of the probes that held and the residual risk
  (volume exhaustion) that is accepted and why.
- Six regression tests covering all three findings, including the
  defense-in-depth path where a record bypasses source validation.

## [0.10.1] - 2026-08-05

### Fixed
- Two mermaid diagrams failed to parse on GitHub. `;` separates statements in
  mermaid, so one inside a sequence note and one inside a flowchart label
  truncated the statement and the whole block rendered as an error box. Both
  introduced in v0.10.0.
- `tests/test_sprint10.py` now fails the build on a semicolon inside a mermaid
  statement. This class of defect is invisible to `make verify`: the markdown is
  valid, the disclosure lint passes, and the breakage appears only when the
  forge renders the page. `classDef` and `class` lines are the exception, since
  they end in `;` legitimately.

## [0.10.0] - 2026-08-05

Consistency pass against the sibling repositories in the same portfolio, plus
the packaging defect that review turned up.

### Changed
- **One package instead of five.** `collectors`, `active`, `scoring`,
  `inventory` and `reporting` were top-level packages, so installing this wheel
  planted five collision candidates in site-packages under names generic enough
  that a collision was a matter of time. They now live under `ananke`. The
  distribution is still `pqc-crypto-agility-assessment` and the console scripts
  are still `pqc-*`: a slug is a search term and a command is typed by hand,
  while an import path is a namespace and needs to be unique rather than
  descriptive. **Breaking for anyone importing the modules directly.**
- The refactor exposed two latent couplings, both fixed: `weights.yaml` was
  addressed through the repository root, which an installed wheel does not have,
  and the disclosure guard's repository sentinel tested for a directory that no
  longer exists.
- Documentation filenames are uppercase, matching `phantomatics`:
  `MECHANISMS.md`, `METHODOLOGY.md`, `MVP.md`. Generated output stays lowercase
  (`report.md`), so the case now distinguishes a design document from an
  artefact.
- The naming convention in `README.md` was wrong and is rewritten. It claimed
  codenames stay out of package names, which `phantomatics` does not do and
  this release no longer does either.
- `README.md` declared three provenance labels. `reported` shipped in v0.9.0 and
  the list was never updated.
- `requirements.txt` states that `pyproject.toml` is the source of truth rather
  than silently competing with it.

### Added
- `SECURITY.md`: how to report a defect in the guard privately, what counts as
  a vulnerability here, and why silent metric distortion is treated as one.
- `docs/THREAT-MODEL.md`: five adversaries against the two promises this project
  is published on, including the client who supplies a convenient inventory, and
  what the residual risk is in each case.
- `docs/ARCHITECTURE.md`: component view with a block-to-documentation index,
  maintained as a table so a rename cannot go stale unnoticed. Needed since the
  pipeline stopped being a line in v0.9.0.
- `pqc-fixture`: three synthetic estates. `clean` is a plausible estate,
  `partial` is the paying adversary who omits what would fail, `hostile` has
  filenames contradicting subjects, underscore-glued identity, an empty subject
  and a file that is not a certificate. Borrowed from `phantomatics`, where the
  adversarial world is what validated the design and the clean world only ever
  confirmed the obvious.
- `tests/test_sprint10.py`: twelve cases running the offline path against those
  estates. The load-bearing ones are that the hostile world neither crashes nor
  puts a host identifier into the aggregate, and that the partial world is
  indistinguishable from a complete one on the data alone.
- Prose-only allowlist for the repository's own publishing infrastructure. A
  CI badge is a URL to the forge; `github.com` in a collected record is still a
  host identifier and still fails the structural guard.
- CI badge, `NOTICE`.

## [0.9.0] - 2026-08-05

The collector stops being welded to Certificate Transparency. An operator can
now hand over a directory of their own certificates and get the same analysis,
offline, with no network peer at all.

### Added
- `collectors/sources.py`: a source seam. A source declares not only where
  bytes come from but the regime that follows from it - `provenance`,
  `modality`, and whether the estate is first party.
- `LocalPemSource`: reads PEM and DER from a directory. Host identity is taken
  from the certificate subject, falling back to SAN, never from the filename: a
  filename is a label someone typed, the subject is part of the signed object.
  A certificate with neither is keyed `unidentified-<stem>` rather than given an
  invented host.
- `CrtShSource`: the previous behaviour, unchanged, behind the same interface.
- `--source {crtsh,local-pem}`, `--pem-dir`, `--sector` on `pqc-collect`.
- `tests/test_sprint9.py`: 14 cases covering host derivation, per-host grouping,
  the first-party regime, store compatibility, and the suppression invariant.

### Changed
- **The aggregate reports the regime it was produced under** instead of the
  constants `measured` and `A_passive_public_ct`. A CT sample and an operator's
  declared estate are different epistemic objects and the output now says which
  one it is.
- **New provenance value: `reported`.** Certificates in an operator's dump are
  parsed by us, so their fields stay `measured`; the *completeness* of the set
  is the client's claim and nothing observed. The label sits at the set level,
  not the field level.
- Minimum bucket size is relaxed only for a first-party estate, and only
  because a source asserted it. Suppression protects a third party from being
  identified through a sector of one; a paying operator has nobody to be
  protected from, and suppression there would delete the deliverable. There is
  deliberately no argument that disables suppression for CT data, and a test
  fails the build if one appears.
- Aggregation refuses a raw store holding more than one modality
  (`MixedModalityError`) rather than summing them into a number with no
  referent. An unrecognised modality tag resolves to the conservative row, and
  a store written before this release still aggregates as passive CT.

### Note
This closes the gap between the repository and an external commitment: the
offline first-party path was described before it existed.

## [0.8.1] - 2026-08-04

Documentation-only patch. No code changes; `collectors/`, `scoring/`,
`inventory/`, `active/` and `reporting/` are byte-identical to 0.8.0.

The 0.8.0 tag was cut before the codename and release criteria landed, so the
published sdist and wheel carried a `README.md` without either. Rather than move
a published tag, this releases the documentation state as a patch.

### Added
- Project codename **ANANKE** recorded in `README.md` (*On the name*, plus the
  naming convention that keeps codenames out of the slug, package name and
  console scripts), and in the headers of `METHODOLOGY.md`, `MECHANISMS.md` and
  `MVP.md`.
- `docs/MVP.md`: release criteria for the three candidate audiences.
- `CONTRIBUTING.md`: new documentation must be staged before `make verify`,
  since the derived filename allowlist reads `git ls-files` and an untracked
  file is deliberately not yet a known filename.

### Verified
- The derived allowlist resolves through `git ls-files` under GitHub Actions,
  not only through the filesystem fallback used in local containers. Previously
  an inference; now observed on a green run against the 0.8.0 tree.

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
- **Project codename: ANANKE**, after Stanislaw Lem's story of that name. The
  repository slug, package name and console scripts are unchanged and stay
  descriptive: the naming convention keeps codenames in documentation and out of
  anything CI, PyPI or an import path resolves. Rationale in `README.md` under
  *On the name*.
- `docs/MVP.md`: release criteria for the three candidate audiences, each with a
  definition of done, a distance estimate and its blockers. `TODO.md` records
  what is not done; this records what finished means, which was unstated for
  eight sprints.

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
- `docs/MECHANISMS.md`: how each mechanism works, for readers who want the
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
