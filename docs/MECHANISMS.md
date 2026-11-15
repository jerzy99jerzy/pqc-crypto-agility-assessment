# Mechanisms

Project codename: ANANKE.

Version 2.0, 2026-11-15. Sections follow the pipeline in order. The six
sections appended in sprints 9 to 13 (sources, sector labels, the decision
layer, HTML rendering, the cross-check, the key inventory) now sit where they
run, and module paths follow the `ananke` namespace introduced in v0.10.0.

How the pipeline works, mechanism by mechanism. `README.md` states the thesis
and the scope; `METHODOLOGY.md` covers the epistemic labels and the reasoning
behind the design; this document describes what the code does.

Every mechanism below is implemented and exercised by the test suite. Where a
mechanism cannot be verified offline, the section says so.

---

## 0. Diagram map

The two diagrams in `README.md`, Architecture (data flow) and Runtime
(sequence), use the same node names. Each maps to a source module and to the
section of this document that explains it. If a diagram node is added or
renamed, this table changes in the same commit.

| Diagram node | Source module | Section |
|---|---|---|
| `select_targets` / selection manifest | `ananke/collectors/select_targets.py` | 1 |
| `CrtShSource`, `LocalPemSource`, `local-pem` | `ananke/collectors/sources.py` | 2 |
| `crt.sh` / passive collection, `certparse` | `ananke/collectors/crtsh.py`, `ananke/collectors/certparse.py` | 3 |
| `store` (`data/raw`) | `ananke/collectors/store.py` | 4 |
| `passive_cert.aggregate` / sector aggregates | `ananke/collectors/passive_cert.py`, `ananke/config.py` | 5 |
| disclosure guard | `ananke/collectors/disclosure.py` | 6 |
| `hndl_score` / sector scores | `ananke/scoring/hndl_score.py`, `ananke/scoring/weights.yaml` | 7 |
| `handshake_demo` (modality B) | `ananke/active/handshake_demo.py` | 8 |
| `pqc_capability` | `ananke/inventory/pqc_capability.py`, `config/pqc_capability.yaml` | 9 |
| `keys` (modality E) | `ananke/collectors/keys.py` | 10 |
| `crosscheck` | `ananke/collectors/crosscheck.py` | 11 |
| `detection/` | `detection/sigma/`, `detection/kql/`, `detection/spl/` | 12 |
| `build_report`, `html_report` / `docs/report.md` | `ananke/reporting/` | 13 |

The Runtime diagram shows the six `make` targets in execution order and the two
points where a run halts itself: the rate-limited collection loop (section 3)
and the fail-closed guard (section 6). Modality B, the key inventory, the
cross-check and the detection pack sit outside that main sequence.

---

## 1. Selection: establishing a denominator

`ananke/collectors/select_targets.py`

A percentage needs a stated denominator, so selection produces an artefact as
well as a target list. One run writes a working target list, which is
git-ignored, and a **selection manifest**, which is committed.

The manifest records the input ranking's file name and SHA-256, the filters
applied, the SHA-256 of the classification ruleset, per-sector counts, the
minimum bucket size the run was given, and the number of domains that matched
rules from more than one sector. It contains no domain names, so a reader can
challenge the sampling without being handed the sample.

Classification is substring-based and therefore collides: a token like `gaz`
matches both an energy company and a newspaper. First match wins, but every
match is collected, so collisions are **counted and published** rather than
resolved silently.

The manifest also carries the sampling bias in writing: resolver-traffic
rankings overrepresent consumer web properties and underrepresent APIs and
machine-to-machine endpoints, which is where long confidentiality horizons
concentrate. The method therefore undercounts the highest-HNDL assets, and the
note travels with the numbers.

The minimum bucket size recorded here is not compared with the one aggregation
uses. The first field run selected at 5 and aggregated at 1, and nothing
noticed (T19, `docs/FIELD-RUN.md`).

## 2. Sources and the regime they carry

`ananke/collectors/sources.py`

A source answers two questions: where certificates come from, and what may be
claimed about the set once they arrive.

`CrtShSource` reads Certificate Transparency. Its records are `measured`: the
log is an independent public record, and nobody in the commercial transaction
chose what it contains. It is not first party, so sector buckets below the
minimum size are suppressed.

`LocalPemSource` reads a directory of PEM or DER files supplied by an operator.
No network peer exists on this path at all. Host identity comes from the
certificate subject and then from SAN, never from the filename: a filename is a
label somebody typed, while the subject is inside the signed object. A file with
neither is keyed `unidentified-<stem>`, because inventing a host to make the
output tidy is the failure this project exists to avoid.

Its records are `reported`, and the distinction is narrow but load-bearing.
Every certificate in the dump is parsed here, so the fields are measured in the
ordinary sense. What is not measured is that the dump is the estate. That is a
claim by the party commissioning the report, and the label sits at the level of
the set rather than the field.

First-party status is the only thing that relaxes minimum bucket size, and only
a source may assert it. Suppression exists so that a third party cannot be
identified through a sector of one. An operator paying for a report on their own
estate has nobody to be protected from, and suppressing there would delete the
deliverable while protecting no one. No argument turns suppression off for CT
data, and a test fails the build if one is added.

`_regime` resolves a store to one modality, one provenance and one first-party
flag. Aggregation refuses a store holding records from more than one modality
(`MixedModalityError`): a percentage across a public sample and the same
percentage across one operator's declared estate are different statements, and
summing them yields a number with no referent.

## 3. Passive collection: certificate dimensions from public CT

`ananke/collectors/crtsh.py`, `ananke/collectors/certparse.py`,
`ananke/collectors/passive_cert.py`

Certificate Transparency logs are a public, append-only record. Reading them
generates zero traffic toward the domain owner's infrastructure.

Two API surfaces are used: log-entry metadata, and the certificate itself. The
metadata surface does **not** expose key or signature algorithm. Reporting
issuer and expiry from metadata while implying the key algorithm was measured is
a common shortcut in this space; here the leaf is fetched and parsed, so the
algorithm is measured.

Retention is scoped to current posture: the client excludes expired entries and
keeps the two most recently logged leaves per host by default (`--leaves`). A
run meant to read issuance history has to widen both before it starts
(`docs/ROTATION-CADENCE.md`, `docs/FIELD-RUN.md`).

Upstream requests are rate-limited with a minimum interval plus jitter, and
retried with exponential backoff on 429 and 5xx. crt.sh is a free community
service, and the default rate is deliberately low.

Parsing yields a flat record: subject, issuer, validity window, key algorithm and
parameter, signature algorithm and OID, and whether validity extends past the
configured milestone.

The vulnerability flags are **tri-state**:

| value | meaning |
|---|---|
| `True` | a Shor-breakable family (RSA, EC, DSA, EdDSA, X25519/X448) |
| `False` | a recognised PQC algorithm (ML-KEM, ML-DSA, SLH-DSA by OID) |
| `None` | the algorithm could not be identified |

An unidentified algorithm must never resolve to `False`. Downstream, `False`
reads as *measured post-quantum*: the aggregator counts it as a PQC indicator
and the vulnerable-key count shrinks. A parser that guesses `False` converts its
own ignorance into evidence of PQC adoption, in the direction that flatters the
estate. Unknown stays unknown, prices as 0.5 in scoring with provenance
`unknown`, and appears as a visible bucket in the aggregate.

The parser never raises. One malformed certificate records a `parse_error` and
the batch continues, so the awkward input costs one record rather than the run.

## 4. Store: resumable, atomic, host-scoped

`ananke/collectors/store.py`

One JSON file per host, so a rerun resumes at host granularity. Writes go
through a temporary file, `fsync`, then `os.replace`, which is atomic within a
filesystem on POSIX: an interrupted run never leaves a torn record. A file that
fails to parse is treated as absent and rewritten rather than crashing the run.
Store keys are capped in length with a digest suffix, so a SAN longer than the
filesystem's name limit cannot stop the write.

Freshness is TTL-based, so reruns do not re-hit the upstream API for data
already held. The store lives under `data/raw/`, which is git-ignored. Only
sector-level aggregates are committed.

## 5. Aggregation: sector counts, labels, the decision layer

`ananke/collectors/passive_cert.py`, `ananke/config.py`

Aggregation collapses the host-level store into sector counts: key-algorithm
distribution, signature algorithms, quantum-vulnerable counts, validity buckets,
and PQC indicators. A sector holding fewer than the minimum number of hosts is
**suppressed entirely** rather than reported with n=1, because a bucket of one
is a named organisation wearing a sector label.

The minimum is checked against `hosts_observed`. A labelled sub-population can
be smaller: on the 2026-08-06 run, education cleared the threshold at 12 hosts
observed while its quantum-vulnerable figure described 3 hosts with a
certificate. Which count the minimum should apply to is open (T19). The
aggregate also cannot yet tell a host with no certificate in CT from a host the
run never reached (T20).

**Sector labels.** A sector names a category, never an organisation. The label
supplied with the offline source becomes a dictionary key in the committed
aggregate, and keys are a position the guard's value scan does not walk, so the
label is validated at the source: lowercase letters, digits, hyphen and
underscore, at most forty characters, no dots. The dot is excluded because it is
what makes a string host-shaped. Aggregation re-checks every sector key
independently, so the property holds even for a record written by code that
skipped the first check.

**The decision layer.** The aggregate carries, per sector, the split a
migration plan is built from: certificates whose expiry falls on or before the
configured milestone (self-resolving: normal renewal replaces them, and the only
required action is a changed issuance policy) against certificates that outlive
it (intervention: no scheduled renewal would replace them). The split is
recomputed from `not_after` against the milestone passed at aggregation time,
never read from a stored flag, so a store collected under one milestone
reclassifies under another without recollecting. Alongside it: the expiry-year
distribution of the intervention class, rotation bands, median validity with a
rotations-before-milestone figure, and the issuer distribution. The issuer count
uses `issuer_o` only, because on a self-signed certificate the issuer is the
subject and counting CNs would carry host identity into committed output.

The milestone is read once, by `ananke/config.py`, from `weights.yaml` (default
2030-12-31). `--milestone` overrides it for one run, and each record carries the
milestone it was parsed under.

## 6. The disclosure guard

`ananke/collectors/disclosure.py`, `tests/lint_disclosure.py`

The scope statement is worth as much as its enforcement, so enforcement is in
code and fails closed. Every writer that produces counts calls the guard before
it writes. The handshake record, which names allowlisted hosts by design, is the
exception (section 8). The guard has two checks:

- **Structural.** A recursive walk rejects keys known to carry host identity
  (`host`, `subject_cn`, `san_dns`, `sha256`, `serial_number`, device columns
  from endpoint exports, and so on) and rejects values that look like
  hostnames, IPv4 literals or IPv6 literals. Byte strings are decoded and walked
  like strings, because `cryptography` returns bytes for a name attribute it
  declines to decode.
- **Statistical.** Bucket sizes are re-checked against the declared minimum at
  write time, independently of the aggregation logic that produced them.

Neither host pattern is anchored on `\b`. Underscore is a word character, so `\b`
never fires between `_` and a letter, and a match may only begin at a boundary:
`acme_bank.pl` and `host_10.0.0.1` matched nothing at all until sprint 8. The
boundaries are written by hand, treating `_` as the delimiter it is in practice
while refusing to start mid-run inside a longer name.

IPv6 is nominated by a loose pattern and decided by `ipaddress`. A regex loose
enough to catch every valid form also catches clock times and MAC addresses,
while validation is exact by construction: `12:34:56` is rejected because it is
not an address. `::` and `::1` are exempt because they identify nobody.

Certificate fingerprints are host identifiers, and the guard currently catches
them by field name (`sha256`) only. A 64-character hex value under another key,
or inside a free-text string, passes. Value detection is T25.

**The prose scan** runs over every tracked markdown file, minus hosts declared
as `self` or `reference` in the allowlist, since naming a positive control is
part of the method. Until 0.15.4 it read `docs/` and three root files from a
list, which left five tracked documents unscanned. It strips
fenced blocks and inline code first, because a guard that flags every dotted
identifier in the documentation gets switched off; the structural guard, which
has no such exemption, is what runs over collected data.

The two scans also differ in what counts as a filename. Several extensions the
repository uses are live ccTLDs (`.md` is Moldova, `.py` Paraguay, `.io` the
British Indian Ocean Territory), so exempting them as a class would open a
blind spot where a domain is most likely to be mistaken for a file. The prose
scan derives the permitted names from the tracked file list (`git ls-files`,
with a scoped filesystem walk as fallback for a source tarball): a token is
benign if a file by that name is in the repository. The prose scan also admits
the forge (`github.com`, for the CI badge) and, since 0.15.3, a short reviewed
list of citation hosts: the standards bodies and publishers the documentation
links to, by exact name. The structural guard consults none of these sets,
because that is the path collected data travels. `tests/lint_prose.py` fails the
build on an entry in either prose list that no tracked document needs.

`tests/lint_disclosure.py` runs the same guards from the outside over files
already on disk, in CI. The writers can be bypassed by hand-editing a JSON file;
the external lint cannot.

## 7. HNDL scoring

`ananke/scoring/hndl_score.py`, `ananke/scoring/weights.yaml`

The model has no access to data classification and does not pretend to. It
reads host records from the raw store, combines measured certificate dimensions
with one named assumption, projects the result onto the configured milestone,
and writes sector-level scores through the guard. Every weight, horizon,
threshold and band lives in `weights.yaml`; a weight hardcoded in the module is a
bug, and a test asserts as much.

Five components: key vulnerability, signature vulnerability, horizon pressure,
whether the certificate outlives the milestone, and rotation agility inferred
from validity length. Each is emitted with its own value, weight, provenance and
contribution, so the composite can be argued with. A composite inherits the
weakest label of its inputs.

**Horizon pressure is the load-bearing assumption.** Sector confidentiality
horizons are analyst estimates derived from statutory retention and secrecy
expectations, not from any observed data inventory. Change them and the ranking
changes.

The saturation cap for that component defaults to `derived`: computed from the
longest configured horizon, so no configured sector can clamp, and the cap
cannot drift out of sync when a horizon is edited. It re-normalises as the
milestone approaches, because the same 30-year horizon buys more exposure every
year that passes. A fixed cap is still accepted, since an analyst may want
saturation on purpose.

`--validate-config` reports configuration problems by severity. Top-end
saturation collapses the sectors the model exists to rank, so it is an
**error** and fails CI. Bottom-end flooring is the expected consequence of a
horizon shorter than the distance to the milestone, where a sector carries no
HNDL exposure at all, so it is a **warning** that the output states.

## 8. Active demonstration

`ananke/active/handshake_demo.py`

One TLS 1.3 handshake per target, offering the hybrid group `X25519MLKEM768`
(codepoint `0x11EC`), reading back the group the server negotiated.

It is not a scanner: no port enumeration, no discovery, no rate-multiplied
sweep. Targets must appear in an allowlist under `self` (infrastructure the
operator owns and is authorised to test) or `reference` (public implementations
serving internet-scale traffic, used as positive controls). Anything else is
refused before a socket is opened, and the scope gate runs **before** the
capability check, so a refusal never depends on which OpenSSL happens to be
installed.

The probe requires OpenSSL 3.5 or later and refuses to run on anything older.
The likeliest failure of this class of test is misattributing a *client*
limitation to the server, and an old client would produce a confident, wrong
"no PQC support" result.

Output parsing is split into a pure function so it can be tested against
captured transcripts without a live OpenSSL 3.5 client. The test fixtures are
hand-written approximations and are labelled as such; they are never evidence
about any host.

HelloRetryRequest is *inferred* from the client writing ClientHello twice, and
is labelled `inference` in the record rather than presented as measured.

The output record names the allowlisted hosts it probed, by design. That is
also why it cannot sit under `data/aggregates/` as things stand: the external
lint walks every file there with the structural guard, which rejects the `host`
key (probed 2026-11-15, T1).

## 9. Endpoint capability resolution

`ananke/inventory/pqc_capability.py`, `config/pqc_capability.yaml`

This answers the question that gates a migration plan: on how many hosts is the
crypto stack capable of a hybrid key exchange at all. A host below the threshold
is a package-upgrade ticket, not a crypto-policy ticket, and separating those
two populations is most of the work.

It exists because KQL cannot compare semantic versions safely: `3.10` is not
less than `3.5` as a float, and treating it as one misclassifies every host
that has already been upgraded. Versions are tokenised into numeric and
alphabetic runs compared within their own type, which handles `3.10.1`, OpenSSL
letter releases like `1.1.1w`, and distribution suffixes like `3.5.0+deb12u2`.
Trailing numeric zeros are insignificant, so an export that writes `3.5`
against a `3.5.0` threshold resolves as capable.

Verdicts are `capable`, `not_capable`, or `unknown`. **Unknown stays unknown.** A
library with no verified threshold, or a version string that cannot be parsed,
is reported as unknown rather than folded into `not_capable`, because a wrong
threshold reclassifies an entire population and nobody rechecks a number that
already looks plausible. A *sourced negative* is recorded separately: where a
library is confirmed to ship no PQC through a known version,
`pqc_absent_through` marks that ceiling, so a version at or below it resolves to
a measured `not_capable` while anything newer stays `unknown` (this is how
LibreSSL is encoded). Thresholds carry their own provenance, and a library
versioned by commit rather than by release string is unknown by design.

Capability is a precondition, not behaviour: a host running a capable library
may still negotiate a classical group because of policy, middleboxes, or a peer
that offers nothing better. The detection layer measures what happens.

## 10. At-rest key inventory

`ananke/collectors/keys.py`

`pqc-keys` reads an export the operator produces from their own key management
service (Azure Resource Graph, `aws kms describe-key`, GCP KMS list) and emits
sector counts. Nothing in the engagement holds credentials into their vault,
which is why provenance is `reported`.

The classification is tri-state, as everywhere else: an unrecognised key family
resolves to unknown, never to safe.

Wrapping keys and signing keys are counted apart. Wrapping carries
harvest-now-decrypt-later exposure and is what the HNDL score models. Signing
carries forgery after a quantum computer exists, on a horizon set by whatever
requires the signature to remain verifiable, which is frequently longer and
governed by different rules.

Symmetric keys are counted and excluded from migration scope in the same
output, with the reason stated in the payload: AES-256 retains 128 bits of
effective strength against Grover.

The counter to read first is `no_expiry_set`. A key with no expiry is a key
nobody has planned to rotate, and therefore one nobody has planned to migrate.
That is an observation about agility rather than cryptography, and it needs no
capability this project did not already have.

The output is written to `data/aggregates/key_inventory.json` through the guard.
The report does not render it yet (T26).

## 11. Estate cross-check

`ananke/collectors/crosscheck.py`

`pqc-crosscheck` compares two raw stores: the operator's supplied estate and a
passive Certificate Transparency collection over the same operator's domains.
It is the only available control on the completeness of a `reported` set, and
its value comes from being asymmetric.

A host present in CT and absent from the dump is a finding: a publicly trusted
certificate exists and was not declared. A host present in the dump and absent
from CT is not: an internal PKI issues certificates that never reach a public
log, and counting them would generate noise in proportion to how well the
operator runs their own CA. The blind spot, a host both internally issued and
omitted, is stated in the output.

Comparison happens in memory on normalised names (a CT wildcard matches the
declared apex, a trailing dot is the same name, case is not identity), and the
written output is counts. The operator reproduces the list of undeclared hosts
locally from their own two stores; the artefact that leaves the engagement
carries a number. It is written to `data/aggregates/estate_completeness.json`
through the guard, and the report does not render it yet (T26).

## 12. Detection content

`detection/sigma/`, `detection/kql/`, `detection/spl/`

Sigma rules, KQL queries and SPL searches that express PQC posture in the
languages a SOC already runs: TLS sessions negotiating classical-only key
exchange, sessions where a hybrid group *was* negotiated (the burndown
numerator), certificate inventory extending beyond the milestone, stored keys,
and crypto-library capability across endpoints. `tests/validate_sigma.py`
checks the Sigma pack structurally and `tests/validate_spl.py` checks the SPL
pack's discipline, both in `make verify`, so a malformed rule cannot be merged.
Field names are `[inference]` until run against a live tenant;
`detection/README.md` carries the per-artefact status.

## 13. Reporting

`ananke/reporting/build_report.py`, `ananke/reporting/html_report.py`,
`ananke/reporting/limitations.py`

The markdown report is built from committed aggregates only. Missing inputs
render as an explicit "not present" statement rather than a silently omitted
section, so the gaps in a run are visible in its output. Model configuration
warnings are reproduced in the report instead of being filtered out. Before
writing, the rendered markdown is scanned by the prose guard, and the build
fails on any host-like token that is not a declared reference host.

`pqc-report --format html` renders the same aggregates to a single file with no
network requests. For a first-party estate it adds a horizon chart, one segment
per certificate, from `not_before`/`not_after` pairs read from the raw store.
That read is the one sanctioned use of the store outside collection. For a
third-party estate the chart is withheld, because unique date pairs are
searchable in CT (`THREAT-MODEL.md`, A7). The disclosure gate is shared with
markdown and applied to what is content: script and style bodies are stripped
before the prose scan, and every string literal inside script blocks is walked
separately, so embedded data is held to the guard while the surrounding code is
not falsely flagged for `ms.value`.

Both formats print the same limitations list, `ananke/reporting/limitations.py`,
and `make lint-limitations` fails when that list and the README registry
disagree. Until 0.15.2 each renderer kept its own copy, and both still printed
the flat at-rest claim the README had retracted in 0.13.0.

## 14. Provenance, end to end

Five labels, carried in the emitted records rather than only in prose:
`[measured]` read from a certificate, handshake or log without interpretation ·
`[reported]` supplied by the party the report is for, fields parsed here and
completeness theirs · `[inference]` derived from observable proxies ·
`[assumption]` chosen by the analyst, defensible but not observed ·
`[speculation]` explicitly uncertain and carried through rather than resolved.
Scoring also emits `unknown` for a component whose input could not be
identified. In the documents, `tests/lint_prose.py` holds every bracketed label
to the set the README states.

Q-Day is the worked example of the last category: no arrival estimate for a
cryptographically relevant quantum computer is used anywhere in the arithmetic.
The model is anchored to a regulatory milestone, which is a published date.
