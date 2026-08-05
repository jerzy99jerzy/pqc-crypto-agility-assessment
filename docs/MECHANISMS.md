# Mechanisms

Project codename: ANANKE.

How the pipeline works, mechanism by mechanism. `README.md` states the thesis and
the scope; `METHODOLOGY.md` covers the epistemic labels and the reasoning behind
the design; this document describes what the code actually does.

Every mechanism below is implemented and exercised by the test suite. Where a
mechanism cannot be verified in an offline environment, that is stated rather
than glossed.

---

## 0. Diagram map

The two diagrams in `README.md` — the Architecture (data-flow) diagram and the
Runtime (sequence) diagram — use the same node names. Each maps to a source
module and to the section of this document that explains it, so a reader can go
from a box in the picture to the code and to the prose without guessing. This
table is the single source of that mapping; if a diagram node is added or
renamed, it is updated here.

| Diagram node | Source module | Mechanism section |
|---|---|---|
| `select_targets` / selection manifest | `collectors/select_targets.py` | [1. Selection](#1-selection-establishing-a-denominator) |
| `crt.sh` / passive collection | `collectors/crtsh.py`, `collectors/certparse.py` | [2. Passive collection](#2-passive-collection-certificate-dimensions-from-public-ct) |
| `store` (`data/raw`) | `collectors/store.py` | [3. Store](#3-store-resumable-atomic-host-scoped) |
| `passive_cert.aggregate` / sector aggregates | `collectors/passive_cert.py` | [4. Aggregation and the disclosure guard](#4-aggregation-and-the-disclosure-guard) |
| `disclosure guard` (fail-closed) | `collectors/disclosure.py` | [4. Aggregation and the disclosure guard](#4-aggregation-and-the-disclosure-guard) |
| `hndl_score` / sector scores | `scoring/hndl_score.py`, `scoring/weights.yaml` | [5. HNDL scoring](#5-hndl-scoring) |
| Modality B handshake (Architecture only) | `active/handshake_demo.py` | [6. Active demonstration](#6-active-demonstration) |
| `pqc_capability` | `inventory/pqc_capability.py`, `config/pqc_capability.yaml` | [7. Endpoint capability resolution](#7-endpoint-capability-resolution) |
| `detection` (Architecture only) | `detection/sigma/`, `detection/kql/` | [8. Detection content](#8-detection-content) |
| `build_report` / `docs/report.md` | `reporting/build_report.py` | [9. Reporting](#9-reporting) |

The Runtime diagram shows the six `make` targets in execution order and the two
points a run can halt itself: the rate-limited collection loop (section 3) and
the fail-closed guard (section 4). The Architecture diagram adds the two nodes
that stand outside that main sequence — Modality B and the detection pack —
which feed the report and the SOC respectively along independent paths.

---

## 1. Selection: establishing a denominator

`collectors/select_targets.py`

A percentage without a stated denominator is decoration, so selection is an
artefact rather than a step. One run produces two outputs: a working target list,
which is git-ignored, and a **selection manifest**, which is committed.

The manifest records the input ranking's file name and SHA-256, the filters
applied, the SHA-256 of the classification ruleset, per-sector counts, and the
number of domains that matched rules from more than one sector. It contains no
domain names. A reader can therefore challenge the sampling without being handed
the sample.

Classification is substring-based and therefore collides: a token like `gaz`
matches both an energy company and a newspaper. First match wins, but every
match is collected, so collisions are **counted and published** instead of being
resolved silently. A ruleset that hides its collisions produces a denominator
nobody can audit.

The manifest also carries the sampling bias in writing: resolver-traffic
rankings overrepresent consumer web properties and underrepresent APIs and
machine-to-machine endpoints, which is where long confidentiality horizons
concentrate. The method therefore undercounts the highest-HNDL assets, and that
limitation travels with the numbers rather than being left for the reader to
discover.

## 2. Passive collection: certificate dimensions from public CT

`collectors/crtsh.py`, `collectors/certparse.py`, `collectors/passive_cert.py`

Certificate Transparency logs are a public, append-only record. Reading them
generates zero traffic toward the domain owner's infrastructure.

Two API surfaces are used: log-entry metadata, and the certificate itself. The
metadata surface does **not** expose key or signature algorithm. Reporting
issuer and expiry from metadata while implying the key algorithm was measured is
the most common shortcut in this space; here the leaf is fetched and parsed, so
the algorithm is genuinely measured.

Parsing yields a flat record: subject, issuer, validity window, key algorithm and
parameter, signature algorithm and OID, and whether validity extends past the
2030-12-31 milestone.

The vulnerability flags are **tri-state**, and this matters more than it looks:

| value | meaning |
|---|---|
| `True` | a Shor-breakable family (RSA, EC, DSA, EdDSA, X25519/X448) |
| `False` | a recognised PQC algorithm (ML-KEM, ML-DSA, SLH-DSA by OID) |
| `None` | the algorithm could not be identified |

An unidentified algorithm must never resolve to `False`. Downstream, `False`
reads as *measured post-quantum*: the aggregator counts it as a PQC indicator
and the vulnerable-key count shrinks. A parser that guesses `False` therefore
converts its own ignorance into evidence of PQC adoption, in the direction that
flatters the estate. Unknown stays unknown, prices as 0.5 in scoring with
provenance `unknown`, and appears as a visible bucket in the aggregate.

The parser never raises. One malformed certificate records a `parse_error` and
the batch continues, because a collection run that dies on the awkward input
tells you nothing about the other thousand hosts.

## 3. Store: resumable, atomic, host-scoped

`collectors/store.py`

One JSON file per host, so a rerun resumes at host granularity. Writes go
through a temporary file, `fsync`, then `os.replace`, which is atomic within a
filesystem on POSIX: an interrupted run never leaves a torn record. A file that
fails to parse is treated as absent and rewritten rather than crashing the run.

Freshness is TTL-based, so reruns do not re-hit the upstream API for data
already held. The store lives under `data/raw/`, which is git-ignored. Only
sector-level aggregates are ever committed.

Upstream requests are rate-limited with a minimum interval plus jitter, and
retried with exponential backoff on 429 and 5xx. crt.sh is a free community
service; the default rate is deliberately low.

## 4. Aggregation and the disclosure guard

`collectors/passive_cert.py`, `collectors/disclosure.py`

Aggregation collapses the host-level store into sector counts: key-algorithm
distribution, signature algorithms, quantum-vulnerable counts, validity buckets,
and PQC indicators. A sector holding fewer than the minimum number of hosts is
**suppressed entirely** rather than reported with n=1, because a bucket of one
is a named organisation wearing a sector label.

The scope statement is worth exactly as much as its enforcement, so enforcement
is in code and fails closed. Before an aggregate is written, it passes two
checks:

- **Structural.** A recursive walk rejects keys known to carry host identity
  (`host`, `subject_cn`, `san_dns`, device columns from endpoint exports, and
  so on) and rejects strings that look like hostnames or IPv4 literals. Both
  patterns are needed: a hostname regex requires an alphabetic final label, so
  a dotted quad passes straight through one written only for names.
- **Statistical.** Bucket sizes are re-checked against the declared minimum at
  write time, independently of the aggregation logic that produced them.

Neither pattern is anchored on `\b`. Underscore is a word character, so `\b`
never fires between `_` and a letter, and a match may only begin at a boundary:
`acme_bank.pl` and `host_10.0.0.1` matched nothing at all until sprint 8. The
boundaries are written by hand instead, treating `_` as the delimiter it is in
practice while still refusing to start mid-run inside a longer name.

A prose variant scans committed markdown, minus hosts declared as `self` or
`reference` in the allowlist, since naming a positive control is part of the
method. The prose scan strips fenced blocks and inline code first, because a
guard that flags every dotted identifier in the documentation gets switched off
within a week; the structural guard, which has no such exemption, is what runs
over collected data.

The two scans also differ in what counts as a filename. Several extensions the
repository uses are live ccTLDs (`.md` is Moldova, `.py` Paraguay, `.io` the
British Indian Ocean Territory), so exempting them as a class would open a
blind spot exactly where a domain is most likely to be mistaken for a file.
The prose scan resolves this by deriving the permitted names from the tracked
file list (`git ls-files`, with a scoped filesystem walk as fallback for a
source tarball): a token is benign if a file by that name is actually in the
repository. The structural guard does not consult that set at all and keeps
zero filename exemptions, because that is the path collected data travels.

`tests/lint_disclosure.py` runs the same guards from the outside over files
already on disk, in CI. The writers can be bypassed by hand-editing a JSON file;
the external lint cannot.

## 5. HNDL scoring

`scoring/hndl_score.py`, `scoring/weights.yaml`

The model has no access to data classification, so it does not pretend to. It
combines measured certificate dimensions with one named assumption and projects
the result onto the regulatory milestone. Every weight, horizon, threshold and
band lives in `weights.yaml`; a weight hardcoded in the module is a bug, and a
test asserts as much.

Five components: key vulnerability, signature vulnerability, horizon pressure,
whether the certificate outlives the milestone, and rotation agility inferred
from validity length. Each is emitted with its own value, weight, provenance and
contribution, so the composite can be argued with rather than believed. A
composite inherits the weakest label of its inputs.

**Horizon pressure is the load-bearing assumption.** Sector confidentiality
horizons are analyst estimates derived from statutory retention and secrecy
expectations, not from any observed data inventory. Change them and the ranking
changes.

The saturation cap for that component defaults to `derived`: computed from the
longest configured horizon, so no configured sector can clamp, and the cap
cannot drift out of sync when a horizon is edited. It also re-normalises as the
milestone approaches, which is correct — the same 30-year horizon buys more
exposure every year that passes. The alternative, a fixed cap, is still
accepted, because an analyst may deliberately want saturation.

`--validate-config` reports configuration problems by severity, and the
distinction is deliberate. Top-end saturation collapses the sectors the model
exists to rank, so it is an **error** and fails CI. Bottom-end flooring is the
expected consequence of a horizon shorter than the distance to the milestone —
those sectors carry no HNDL exposure at all — so it is a **warning** that must be
stated rather than a defect to fix.

## 6. Active demonstration

`active/handshake_demo.py`

One TLS 1.3 handshake per target, offering the hybrid group X25519MLKEM768
(IANA 0x11EC, RFC 9794), reading back the group the server negotiated.

It is not a scanner: no port enumeration, no discovery, no rate-multiplied
sweep. Targets must appear in an allowlist under `self` (infrastructure the
operator owns and is authorised to test) or `reference` (public implementations
serving internet-scale traffic, used as positive controls). Anything else is
refused before a socket is opened, and the scope gate runs **before** the
capability check, so a refusal never depends on which OpenSSL happens to be
installed.

The probe requires OpenSSL 3.5 or later and refuses to run on anything older.
The most likely failure mode of this class of test is misattributing a *client*
limitation to the server, and an old client would produce a confident, wrong
"no PQC support" result.

Output parsing is split into a pure function so it can be tested against
captured transcripts without a live OpenSSL 3.5 client. An untested parser that
only ever sees failure output is a parser that will misread the one result that
matters. The test fixtures are hand-written approximations and are labelled as
such; they are never evidence about any host.

HelloRetryRequest is *inferred* from the client writing ClientHello twice, and
is labelled `inference` in the record rather than presented as measured.

## 7. Endpoint capability resolution

`inventory/pqc_capability.py`, `config/pqc_capability.yaml`

This answers the question that gates a migration plan: on how many hosts is the
crypto stack capable of a hybrid key exchange at all. A host below the threshold
is a package-upgrade ticket, not a crypto-policy ticket, and separating those
two populations is most of the work.

It exists because KQL cannot compare semantic versions safely — `3.10` is not
less than `3.5` as a float, and pretending otherwise misclassifies every host
that has already been upgraded. Versions are tokenised into numeric and
alphabetic runs compared within their own type, which handles `3.10.1`,
OpenSSL letter releases like `1.1.1w`, and distribution suffixes like
`3.5.0+deb12u2`. Trailing numeric zeros are insignificant, so an export that
writes `3.5` against a `3.5.0` threshold resolves as capable rather than being
silently downgraded.

Verdicts are `capable`, `not_capable`, or `unknown`. **Unknown stays unknown.**
A library with no verified threshold, or a version string that cannot be parsed,
is reported as unknown rather than folded into `not_capable`, because a wrong
threshold reclassifies an entire population and nobody rechecks a number that
already looks plausible. A *sourced negative* is distinct from unknown and is
recorded as such: where a library is confirmed to ship no PQC through a known
version, `pqc_absent_through` marks that ceiling, so a version at or below it
resolves to a measured `not_capable` while anything newer stays `unknown` rather
than being assumed incapable on a release the source never examined (this is how
LibreSSL is encoded). Thresholds carry their own provenance, and a library
versioned by commit rather than by release string is unknown by design.

Capability is a precondition, not behaviour: a host running a capable library
may still negotiate a classical group because of policy, middleboxes, or a peer
that offers nothing better. That is what the detection layer is for.

## 8. Detection content

`detection/sigma/`, `detection/kql/`

Sigma rules and KQL queries that express PQC posture in the language a SOC
already runs: TLS sessions negotiating classical-only key exchange, sessions
where a hybrid group *was* negotiated (the burndown denominator), certificate
inventory extending beyond the milestone, and crypto-library capability across
endpoints. `tests/validate_sigma.py` validates the pack structurally in CI, so a
malformed rule cannot be merged.

## 9. Reporting

`reporting/build_report.py`

The report is built only from committed aggregates. It has no access to the raw
host-level store by construction rather than by discipline: a generator that
cannot read host data cannot leak host data.

Missing inputs render as an explicit "not present" statement rather than a
silently omitted section, so the gaps in a run are visible in its output. Model
configuration warnings are reproduced in the report instead of being filtered
out. Before writing, the rendered markdown is scanned by the prose guard, and
the build fails on any host-like token that is not a declared reference host.

## 10. Provenance, end to end

Four labels, carried in the emitted records rather than only in prose:

`[measured]` read from a certificate, handshake or log without interpretation ·
`[inference]` derived from observable proxies · `[assumption]` chosen by the
analyst, defensible but not observed · `[speculation]` explicitly uncertain and
carried through rather than resolved.

Q-Day is the worked example of the last category: no arrival estimate for a
cryptographically relevant quantum computer is used anywhere in the arithmetic.
The model is anchored to a regulatory milestone, which is an observable fact,
rather than to a forecast, which is not.


## Sources and the regime they carry

A source answers two questions, not one. Where do certificates come from, and
what may be claimed about the set once they arrive.

`CrtShSource` reads Certificate Transparency. Its records are `measured`: the
log is an independent public record, and nobody in the commercial transaction
chose what it contains. It is not first party, so sector buckets below the
minimum size are suppressed.

`LocalPemSource` reads a directory of PEM or DER files supplied by an operator.
No network peer exists on this path at all. Host identity comes from the
certificate subject and then from SAN, never from the filename: a filename is a
label somebody typed, while the subject is inside the signed object. A file with
neither is keyed `unidentified-<stem>`, because inventing a host to make the
output tidy is exactly the failure this project exists to avoid.

Its records are `reported`, and the distinction is narrow but load-bearing. Every
certificate in the dump is parsed here, so the fields are measured in the
ordinary sense. What is not measured is that the dump is the estate. That is a
claim by the party commissioning the report, and the label sits at the level of
the set rather than the field.

First-party status is the only thing that relaxes minimum bucket size, and only
a source may assert it. Suppression exists so that a third party cannot be
identified through a sector of one; an operator paying for a report on their own
estate has nobody to be protected from, and suppressing there would delete the
deliverable while protecting no one. There is no argument that turns suppression
off for CT data, and a test fails the build if one is added.

Aggregation refuses a store holding records from more than one modality. A
percentage across a public sample and the same percentage across one operator's
declared estate are different statements, and summing them yields a number with
no referent.


### Sector labels

A sector names a category, never an organisation. The label supplied with the
offline source becomes a dictionary key in the committed aggregate, and keys are
a position the guard's value scan does not walk, so the label is validated at
the source instead: lowercase letters, digits, hyphen and underscore, at most
forty characters, no dots. The dot is excluded deliberately, because it is
exactly what makes a string host-shaped. Aggregation re-checks every sector key
independently, so the property holds even for a record written by code that
skipped the first check.


## The decision layer

The aggregate carries, per sector, the split a migration plan is built from:
certificates whose expiry falls on or before the configured milestone
(self-resolving: normal renewal replaces them, the only required action is a
changed issuance policy) against certificates that outlive it (intervention:
no renewal is scheduled that would replace them). The split is recomputed from
`not_after` against the milestone passed at aggregation time, never read from
a stored flag, so a store collected under one milestone reclassifies under
another without recollecting. Alongside it: the expiry-year distribution of
the intervention class, rotation bands, median validity with a
rotations-before-milestone figure, and the issuer distribution - `issuer_o`
only, since on a self-signed certificate the issuer is the subject and
counting CNs would carry host identity into committed output.

## HTML rendering

`pqc-report --format html` renders the same aggregates to a single file with
no network requests. The disclosure gate is shared with markdown and applied
to what is actually content: script and style bodies are stripped before the
prose scan, and every string literal inside script blocks is walked
separately, so embedded data is held to the guard while the surrounding code,
which is repository-reviewed, is not falsely flagged for `ms.value`.


## Estate cross-check

`pqc-crosscheck` compares two raw stores: the operator's supplied estate and a
passive Certificate Transparency collection over the same operator's domains.
It is the only available control on the completeness of a `reported` set, and
its value comes entirely from being asymmetric.

A host present in CT and absent from the dump is a finding: a publicly trusted
certificate exists and was not declared. A host present in the dump and absent
from CT is not a finding: an internal PKI issues certificates that never reach a
public log. Treating the second as a discrepancy would generate noise in direct
proportion to how well the operator runs their own CA, which is the opposite of
useful.

Comparison happens in memory on normalised names - a CT wildcard matches the
declared apex, a trailing dot is the same name, case is not identity - and the
written output is counts. The operator can reproduce the list of undeclared
hosts locally from their own two stores; the artefact that leaves the
engagement carries a number.
