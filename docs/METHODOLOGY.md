# Methodology

Project codename: ANANKE. See `README.md` for the naming convention.

Version 15.0, 2026-11-15. The per-sprint ledger that used to head this document
lives in `CHANGELOG.md` alone. This revision updates the HAWK citation in 1.1,
moves the rejected options to `docs/DECISIONS.md`, completes the defect log in
section 9, and points the open items at `TODO.md`.

## 1. Question

How much of an estate is still on quantum-vulnerable public-key cryptography,
how would you find out repeatably, and what can you say about it from data you
are allowed to collect?

The second and third clauses are the work. The first is a number anyone can
produce.

### 1.1 Why agility rather than a one-off migration

The case for crypto-agility does not rest on Q-Day forecasts. It rests on the
observation that a scheme's security estimate can move while the scheme is
still in standardisation, on a timescale shorter than any migration programme.

Dated example. On 2026-07-28 Anthropic
[announced](https://www.anthropic.com/news/discovering-cryptographic-weaknesses)
a key-recovery attack on HAWK, then a third-round candidate in NIST's
additional signature process
([paper, ePrint 2026/1593](https://eprint.iacr.org/2026/1593)). It builds on the
automorphism path opened by van Gent and Pulles
([ePrint 2025/928](https://eprint.iacr.org/2025/928)). The reported gate-count
estimates for the NIST-level parameters fall from 2^150 to 2^108 (HAWK-512) and
from 2^288 to 2^182 (HAWK-1024), while the end-to-end recovery code targets
HAWK-256, a challenge parameter. The attack stays exponential and is not claimed
to generalise to other lattice schemes. On 2026-07-29 the HAWK team withdrew the
scheme in the
[pqc-forum thread](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/2r2u6SbHun4),
stating that the straightforward mitigations, doubling the parameters or moving
to higher-rank modules, make it uncompetitive. NIST's
[round 3 page](https://csrc.nist.gov/Projects/pqc-dig-sig/round-3-additional-signatures)
now lists HAWK as withdrawn.

Provenance on that citation, since this document demands it of everything else:

- `[measured]` The withdrawal and NIST's status change, read from the HAWK
  team's message and NIST's page on 2026-11-15.
- `[reported]` The attack and its cost figures, published by Anthropic with
  code, and accepted by the scheme's designers in the withdrawal message. The
  forum thread also carries a reply from another party reporting its own
  implementation; that implementation was not examined here.
- `[inference]` composed over `[measured]` parts: the companion AES-128 result,
  which covers seven of ten rounds, assumes roughly 2^105 chosen plaintexts, and
  projects its headline speedup from measured components rather than executing
  it end to end.
- Nothing here changes any parameter, weight or collection behaviour in this
  repository. HAWK was never standardised and does not appear in served TLS
  certificates. It is cited as evidence about how fast security estimates move,
  not as an input to the model.

For a migration programme, the cost shape the publisher reported matters more
than the cryptanalysis: roughly USD 100,000 of model compute against several
hundred hours of human verification, with two researchers taking close to a
month to gain confidence in the result `[reported]`. `[inference]` Finding a
candidate weakness has become cheaper than verifying one, so a plan built on a
fixed 2030 target and a static threat estimate inherits estimates that can move
inside its own review cycle.

## 2. Sampling and selection

Selection method must be stated before any number is quoted, otherwise the
denominator is unknowable.

Implemented in `ananke/collectors/select_targets.py`, which produces two
artefacts: the working target list, which is git-ignored, and
`data/aggregates/selection_manifest.json`, which is committed. The manifest
records the ranking file name and its SHA-256, the filters applied, the
classification ruleset and its SHA-256, per-rule hit counts, per-sector totals
and the minimum bucket size the run used. It contains no domain names, so a
reader can challenge the sampling without being handed the sample.

Method `[assumption]`:

1. Pin a public ranking (Tranco) by hash. Downloading it is not automated: the
   list is dated and versioned upstream, and pinning a specific file is the
   point.
2. Filter to the ccTLD or region of interest.
3. Classify into sectors using `config/classification.yaml`, matching exact,
   then contains, then suffix, with an `exclude` list per sector. First match
   wins and the winning rule is recorded.
4. Enforce a minimum bucket size at aggregation. Sectors below it are dropped,
   not reported with n=2. The value is passed to selection and to aggregation
   separately, and nothing compares the two yet (T19).

Rule collisions are counted, not resolved silently. A domain matched by rules
from more than one sector is recorded in the manifest along with the colliding
rule identifiers, because config order decides the winner and the loser
otherwise leaves no trace. The first run of the detector found the Polish stem
`gaz` in the energy ruleset capturing `gazeta`, moving newspapers into the
energy sector. Narrowing the token is the fix; reordering the config only moves
the collision somewhere else.

Sector names in `config/classification.yaml` must match the keys in
`ananke/scoring/weights.yaml`, or scoring falls back to the default horizon
without saying so.

Known limitation `[inference]`: keyword classification of domain names is crude.
A domain containing `bank` is probably a bank; a bank whose domain contains no
listed token is invisible. For anything published, replace the heuristics with
an authoritative register: supervisory lists for financial entities, health
registers for healthcare, the public-entity register for government (T7).

Known bias `[inference]`: Tranco ranks by resolver traffic, which
overrepresents consumer-facing web properties and underrepresents API
endpoints, B2B services and machine-to-machine infrastructure. Since
machine-to-machine traffic is where long confidentiality horizons concentrate,
this sampling method systematically undercounts the highest-HNDL population.
The note is embedded in the manifest so it travels with the numbers.

## 3. Passive collection, Modality A

Source: Certificate Transparency via crt.sh.

The two-surface problem is the main technical reason this collector is more
than fifty lines: the crt.sh JSON search surface returns log entry metadata
only. It does not return the public key algorithm or the signature algorithm.
Those require fetching the certificate itself and parsing it. A report that
quotes issuer and expiry from CT metadata while implying that key algorithm was
measured has not measured key algorithm.

Per host, the collector keeps the most recently logged leaves, deduplicated by
serial. Parsing every historical entry burns the upstream API without adding
signal about *current* posture.

Operational properties, because the shape of the store determines whether a
rerun is cheap:

- one JSON file per host, so the run is resumable at host granularity
- TTL-based freshness, so a rerun does not re-hit the API
- atomic writes via tmpfile plus `os.replace`, so an interrupted run leaves no torn records
- corrupt or partially written files are treated as absent and rewritten

The vulnerability flags on a parsed certificate are tri-state, not boolean:
`True` for a Shor-breakable family, `False` for a recognised PQC algorithm
matched by OID, `None` where the algorithm could not be identified. `False`
reads downstream as *measured post-quantum*, so an unidentified algorithm
resolved to `False` would convert the parser's own ignorance into evidence of
PQC adoption. That shipped once; see section 9.2.

Sources considered and deferred:

- **Censys / Shodan** `[deferred]`. Both would add data the CT logs do not
  carry, notably observed served chains and non-443 TLS. Deferred because the
  platform API surfaces had changed within the year before sprint 1 (2026-07),
  and an untested client written against a remembered schema would put
  unverified claims into the repository. To be added with credentials and a
  live test (T3).
- **Own CT log tailer** `[deferred]`. Removes the crt.sh dependency and the
  rate-limit ceiling. The correct end state, disproportionate for the current
  target counts.

## 4. Active probing, Modality B

One TLS 1.3 handshake per allowlisted target offering `X25519MLKEM768`, then
reading the negotiated group.

Client capability gate: OpenSSL 3.5 or later. Below that, the client cannot
offer the group, and a negative result would be a statement about the client.
The probe refuses to run rather than emit that result.

HelloRetryRequest detection `[inference]`: inferred from the client writing
ClientHello twice in the `-state` trace. The definitive marker is the special
ServerHello random value from
[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) section 4.1.3, which requires
a build with `enable-ssl-trace`. The heuristic is labelled as an inference in
the output record.

What a negotiated group proves `[inference]`: that this endpoint, on this
connection, agreed to a hybrid key agreement. It does not prove that every
endpoint behind the same name does, that non-browser paths do, or that anything
below TLS does.

No `self` host is declared yet, so the method has run against reference
implementations only (T2), and no handshake record has been committed (T1).

## 5. Scoring

See `ananke/scoring/weights.yaml`. Three properties matter more than the
specific numbers:

1. Every constant is in config. A reviewer can rerun with their own weights.
2. Every component carries its own provenance label, and the composite inherits
   the weakest one.
3. The sector confidentiality horizon is named as an assumption in the config,
   in the code, and in every output record. It is the load-bearing input, and
   burying it would make the model look more measured than it is.

The model is anchored to a regulatory milestone, a published date. A Q-Day
estimate is a forecast, and a forecast inside an arithmetic model disappears
from view once the output is quoted.

### 5.1 Defect found and fixed: exposure cap saturation

The first version set `horizon_pressure_cap_years: 20` while the longest
configured horizon was 30. Exposure is measured against the milestone, so at the
time of the fix (late July 2026, with 4.43 years still to run) a 30-year horizon
yielded 25.57 years of exposure and a 25-year horizon yielded 20.57. Both
exceeded the cap, clamped to 1.0, and healthcare, defence and government
therefore scored identically on a component carrying weight 0.30. The model
stopped discriminating among the sectors it exists to rank.

The root cause was two independent numbers in one config that had to agree,
with nothing checking them. The cap is now derived from the longest configured
horizon by default, so it cannot drift, and it renormalises as the milestone
approaches: the same 30-year horizon buys more exposure every year that passes.
A fixed cap is still accepted, because deliberate saturation is a legitimate
analytical choice, but `validate_config` reports which sectors it collapses,
and CI fails on it.

Bottom-end flooring is reported as a warning rather than an error. Sectors whose
horizon is shorter than the distance to the milestone carry no HNDL exposure at
all, so they share a component value by construction. That is a property of the
model, and the validator's severities exist to keep it apart from a defect.

## 6. Rejected options

Recorded in `docs/DECISIONS.md`, each with the condition that would reopen it:
the mass active sweep, the nmap NSE plugin, and the batch orchestrator for the
active probe.

## 7. Disclosure enforcement

The scope statement is executable. `ananke/collectors/disclosure.py` provides a
structural guard used by every writer, and `tests/lint_disclosure.py` runs the
same guard from the outside over committed files, which catches hand-edited
JSON that never passed through a writer.

The decisions inside the guard that are trade-offs rather than obvious choices:

Certificate SHA-256 fingerprints are treated as host identifiers. A fingerprint
resolves back to a domain through the same public CT logs the data came from,
so publishing one undoes the sector aggregation. The cost showed up
immediately: the selection manifest's file hash had to be renamed from `sha256`
to `file_sha256` to pass. A blunt guard whose false positives cost a rename is
preferable to a precise one whose false negatives cost the premise of the
project. The guard catches fingerprints by field name only; a fingerprint value
under another key passes (T25).

The filename exemption deliberately excludes `.sh`, `.py`, `.md`, `.ai`, `.io`,
`.cd` and `.tv`, all of which are live ccTLDs. Allowing them would create a
blind spot where a domain is most likely to be mistaken for a filename.

The prose scan strips fenced blocks and inline code spans, because otherwise
every dotted identifier in the documentation is a false positive and the guard
gets switched off. The accepted consequence is that a hostname hidden inside
backticks in a markdown file would pass the prose scan. Structural JSON output
has no such exemption, and that is where collected data lands.

IPv4 literals are matched by a separate pattern, added in sprint 6, with octets
range-checked to 0-255 so that four-component version strings with a large
final part (`3.5.0.2024`) are not false-positived. The residual collision, a
version string that is also a valid dotted quad such as `1.1.1.1`, is accepted:
a false positive costs a rename, a false negative costs the premise. IPv6,
added in sprint 14, is nominated by a loose pattern and decided by `ipaddress`,
which is exact where a regex would have to guess about clock times and MAC
addresses.

Citation hosts are admitted in the prose scan only, by exact name, since 0.15.3.
Before that no document could link a source, which is a strange property for a
project whose product is provenance. The structural guard still rejects every
one of them inside collected data, and a test pins that.

## 8. Endpoint capability resolution

Two questions get conflated in most PQC readiness material. "Should we adopt
ML-KEM" is a policy question. "Can this host negotiate a hybrid group at all" is
an inventory question with a factual answer, and it decides whether a finding is
a crypto-policy ticket or a package-upgrade ticket.

`ananke/inventory/pqc_capability.py` answers the second one from a software
inventory export. Three properties matter:

Version comparison is component-wise, not float-based. `3.10.1` is above
`3.5.0`; treating versions as decimals inverts that and misclassifies the hosts
that have already been upgraded. OpenSSL letter releases (`1.1.1w`) and
distribution suffixes (`3.5.0+deb12u2`) parse into ordered components rather
than failing. Trailing numeric zeros are insignificant: sprint 6 found that
`3.5` compared below a `3.5.0` threshold, so an export that truncates a zero
resolved an upgraded host as `not_capable`. A non-zero tail still decides, so
`3.5` stays below `3.5.1`. Pre-release suffixes remain a known limitation:
`3.5.0-beta1` sorts above `3.5.0`, because the tokenizer does not distinguish
the semver pre-release marker from build metadata. The verdict errs toward
`capable` and the row stays visible for review.

Thresholds live in `config/pqc_capability.yaml` and carry provenance, with
reference URLs kept in the config. OpenSSL 3.5.0, GnuTLS 3.8.8 and wolfSSL 5.8.0
are `measured` against their release notes. GnuTLS shipped `X25519MLKEM768` as
experimental in 3.8.8 (2024-11-05); wolfSSL shipped the standardised-codepoint
hybrid groups in 5.8.0 (2025-05), which is the interoperable boundary rather
than the first appearance of any hybrid group. NSS is `measured` at 3.118: the
standardised ML-KEM TLS groups landed there (mlkem768x25519 made default,
secp256r1mlkem768 and secp384r1mlkem1024 added), and because the pre-standard
Kyber draft was disabled in 3.116 with no TLS ML-KEM in 3.117, 3.118 is a clean
cutover. LibreSSL is the instructive case: a 2025 survey found no PQC in any
released version through 3.9, which is a *measured negative*. The resolver
expresses it through `pqc_absent_through`: a version at or below the verified
ceiling is a measured `not_capable`, while a newer LibreSSL resolves `unknown`
rather than being assumed incapable on a version the source never examined.
BoringSSL stays `not_applicable`, vendored per product.

Capability is a precondition, not behaviour. A capable host can still negotiate
a classical group because of policy, a middlebox or a peer that never offers a
hybrid one. The measurement of what happens lives in the detection layer; this
module measures what is possible.

Device identifiers are consumed for counting and never emitted. The disclosure
guard was extended with the identity columns that inventory exports carry
(`DeviceId`, `DeviceName`, `Computer`, `hostname`, `fqdn`, `ip`) and runs over
the payload before it is written.

## 9. Defects found by testing

Each entry says what the defect was, why it survived, and the class it belongs
to. `CHANGELOG.md` has the release-by-release detail.

### 9.1 Sprints 2 to 5

`RateLimiter._last` defaulted to `0.0`, so the first call measured its elapsed
time against the epoch of `time.monotonic()`. On Linux that epoch is system
uptime, which is large in practice, so the spurious full-interval sleep before
the first request never appeared in a normal run. It surfaced only when a test
pinned the clock to zero. Fixed to `None` with an explicit first-call branch.

Sigma's `|gte` modifier is numeric-only, so the Zeek x509 expiry comparison
could not take an ISO date and now takes an epoch value with the conversion
documented in the rule.

The classification ruleset shipped with `gaz` in the energy sector, which
captured `gazeta` and moved newspapers into energy. Found by the collision
counter, fixed by narrowing the token rather than reordering the config.

The selection manifest originally used a `sha256` key for the ranking file
hash, which the disclosure guard rejects because certificate fingerprints must
never be published. Renamed to `file_sha256`.

### 9.2 Sprint 6: review of the 0.5.0 tree

All three produced a plausible wrong number rather than a crash, which is the
failure mode that matters for a measurement tool: nothing alerts, the output
looks reasonable, and the error survives into a report. Each has a regression
test that fails against the 0.5.0 code.

**F1.** `certparse` reported `quantum_vulnerable = False` for any key or
signature OID it could not identify. Downstream, `False` is indistinguishable
from a measured PQC algorithm: the aggregator counts `is False` as a PQC
indicator, so every algorithm the parser could not name became evidence of
post-quantum adoption while the vulnerable-key count shrank. The error flattered
the estate under measurement, which is the bias this project exists to avoid.
The flags are now tri-state, and unknown prices as 0.5 in scoring with
provenance `unknown` and appears as its own bucket in the aggregate.

**F2.** `compare_versions("3.5", "3.5.0")` returned -1, so an inventory export
that truncates a trailing zero resolved an already-upgraded host as
`not_capable`. The test suite had frozen the defect as an assertion, with a
comment explaining the wrong behaviour as though it were the contract.

**F3.** The disclosure guard could not see IPv4 literals. `HOSTNAME_RE` requires
an alphabetic final label, so a dotted quad passed through the structural guard
into anything destined for `data/aggregates/`, for five sprints.

### 9.3 Sprint 8: a word boundary is not a name boundary

`HOSTNAME_RE` and `IPV4_RE` were anchored on `\b`. `_` is a word character, so
no boundary exists between `_` and a letter and no match may begin there:
`acme_bank.pl`, `cn=corp_bank.pl` and `host_10.0.0.1` produced no regex match at
all and passed the structural guard silently. This was the third defect in the
same module, and all three had the same shape: the guard was correct about the
class of thing it was looking for and wrong about the alphabet it was looking
in. The boundaries are now written explicitly: underscore is a delimiter on the
left, and a trailing suffix (`bank.pl_backup`) no longer hides a host either.

A second finding, self-inflicted: the CI fix at the end of sprint 7 added
repository document names to `ALLOWED_TOKENS` to stop the prose scan failing on
`LICENSING.md`. That set was shared with the structural guard, so a fix scoped
in its own commit message to prose widened the strict guard as well, and
`{"source": "mechanisms.md"}` became publishable output. The allowlist is now
split by intent: `ALLOWED_TOKENS` stays small and hand-maintained for the
strict guard, while repository filenames are derived from `git ls-files` and
admitted in the prose scan only. Eight of the twenty-four previous entries were
unreachable in any case, since the regex tokenises `hndl_score.py` as
`score.py`; a test now fails the build on a dead entry.

### 9.4 Sprints 10 and 11: identity through side channels

Found by probing the sprint 9 and 10 surface rather than reading it:

| Release | Defect | Class |
|---|---|---|
| 0.10.2 (S1) | `--sector "acme-bank.pl production"` published an organisation name: the label becomes a dictionary key, and the guard walked values, never keys | identity in a position the guard does not inspect |
| 0.10.2 (S2) | the same label carried markup into the HTML renderer | stored injection through an unvalidated label |
| 0.10.2 (S3) | a SAN longer than the filesystem name limit crashed the store write and stopped the run | hostile input that attacks the run, not the number |
| 0.11.0 | counting issuer CNs would have published host identity, because a self-signed issuer is the subject | identity through a derived field, caught before release |
| 0.11.1 (A7) | per-certificate validity pairs in the HTML chart were unique on the reference estate and searchable in CT | suppression of names is not anonymisation of records |

### 9.5 Sprint 13: a claim is a test, not a sentence

The most-read paragraph in the documentation was the least-checked. The "will
not tell you" section claimed no visibility into cryptography at rest while a
Key Vault enumeration query had shipped in sprint 4, and the contradiction
survived three code reviews because each reviewed code and the divergence was
between the code and the prose describing it. Found by a question rather than a
review.

`tests/lint_limitations.py` closes the class: every limitation bullet is
registered with probes and `make verify` fails on drift in either direction.
The principle is stated once, in `ENGINEERING.md` section 0.

### 9.6 Sprint 14: the checker that was not running

Adding `mypy` to the gate produced twelve findings in the first run, eleven of
which were narrowing gaps worth annotating and one of which was a live guard
bypass: `_name_attr` declared `str | None` and could return `bytes`, and the
structural walk inspected `str` only. A subject encoded in a form
`cryptography` declines to decode travelled through the guard untouched. Three
code reviews and an adversarial fixture suite had not found it. The same sprint
closed IPv6 literals, which passed both guards (T14).

### 9.7 Releases 0.14.0 to 0.15.4: the repository's description of itself

| Release | Defect | Why it survived |
|---|---|---|
| 0.14.0 | CI listed checks individually, so two lints ran locally only | the workflow restated `verify` instead of calling it |
| 0.14.1 | the README repository map drew the pre-namespace tree for four sprints | nothing compared the map with the tree |
| 0.14.2 | `make lint` could not fail: `A && B \|\| C` returns C's status | absence read as success, in the target meant to prevent it |
| 0.14.3, 0.15.1 | the layout check's exemptions were enumerated, then derived in one direction only | the derived fix was applied to half the problem, twice |
| 0.15.0, 0.15.1 | the selection manifest recorded a minimum bucket of 5, the aggregate 1, and the changelog misstated what was committed | two invocations, nothing reconciling them (T19) |
| 0.15.2 | the generated report printed the at-rest claim 0.13.0 had retracted; the builder's docstring denied its own raw-store read; `ananke.__version__` said 0.10.0 | the checks covered the README, not the text other code emits |
| 0.15.3 | three documents stated the label set differently; both architecture diagrams were unchanged since 0.6.0 and 0.10.1 and drew the scorer reading the aggregate; the threat model listed two closed holes as open; the README said the guard rejects fingerprints, which it does by key only | the checks covered the limitations section and the map, and nothing else a document says about the tree |
| 0.15.4 | the disclosure lint scanned a hand-written list of documents that left five tracked ones out; two prose allowlist entries were never used, and one could not have matched the badge it was for | the list was written once and never derived, and nothing checked an allowlist entry against use |

### 9.8 Found by probing for this revision (2026-11-15)

- A handshake record shaped as the report renders it fails the structural guard
  on its `host` key, so committing one under `data/aggregates/`, which is T1's
  acceptance test, would turn `lint-disclosure` red.
- The structural guard catches a certificate fingerprint under the `sha256`
  key and passes the same value under any other key or inside a string (T25).
- `README.md` and `docs/ARCHITECTURE.md` drew the scorer reading the sector
  aggregate. It reads the raw store.

## 10. Open items

Tracked in `TODO.md`, which is the single source of truth for what is not done.
The `[verify]` items this document used to list are T4 (Defender and
Application Gateway columns against a live tenant), T5 (Zeek codepoint spelling
for `0x11EC`) and T1 (the handshake success path with an OpenSSL 3.5 client).
The others are T3 (Censys), T7 (authoritative sector registers) and T2 (a `self`
host).
