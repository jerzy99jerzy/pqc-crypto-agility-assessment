# Methodology

Version 5.0, 2026-07-29. Sprint 5: verified capability thresholds, packaging,
coverage floor, detailed runbook. Sprint 4: handshake parser tests, TODO/LICENSE/CONTRIBUTING.
Sprint 3: capability resolution, collection-path tests,
defect log. Sprint 2: selection manifest, exposure-cap fix, executable
disclosure guard, report generation, CI.

## 1. Question

How much of an estate is still on quantum-vulnerable public-key cryptography,
how would you find out repeatably, and what can you honestly say about it from
data you are allowed to collect?

The second and third clauses are the work. The first is a number anyone can
produce.

### 1.1 Why agility rather than a one-off migration

The case for crypto-agility does not rest on Q-Day forecasts. It rests on the
observation that a scheme's security estimate can move while it is still in
standardisation, on a timescale shorter than any migration programme.

Dated example `[measured, not independently reproduced]`: on 2026-07-28
Anthropic published a key-recovery attack on HAWK-256, a challenge parameter of
the HAWK signature scheme, built on the automorphism path opened by van Gent and
Pulles (eprint 2025/928), together with reproducibility artifacts. The reported
gate-count estimates for the NIST-level parameters fall from 2^150 to 2^108
(HAWK-512) and 2^288 to 2^182 (HAWK-1024). Both remain infeasible to attack, the
attack stays exponential rather than polynomial, and it is not claimed to
generalise to other lattice schemes.

Provenance discipline on that citation, since this document demands it of
everything else:

- The result is vendor-published with public code. At the time of writing, the
  NIST pqc-forum thread had no replies and no independent reproduction had been
  identified. Status is therefore `[measured by the publisher, unreproduced]`,
  not `[measured]`.
- The companion AES-128 result covers seven of ten rounds, assumes roughly
  2^105 chosen plaintexts, and its headline speedup is projected from measured
  components rather than executed end to end. That is `[inference]` composed
  over `[measured]` parts.
- Nothing here changes any parameter, weight or collection behaviour in this
  repository. HAWK is not standardised and does not appear in served TLS
  certificates. It is cited as evidence about the *rate of change* of security
  estimates, not as an input to the model.

The operationally relevant part is not the cryptanalysis. It is the cost shape
the publisher reported: roughly $100k of model compute against several hundred
human hours of verification, with two researchers taking close to a month to
gain confidence in the result. Generation got cheap, verification did not. A
migration programme planned around a fixed 2030 target and a static threat
estimate is planning against the wrong variable.

## 2. Sampling and selection

Selection method must be stated before any number is quoted, otherwise the
denominator is unknowable and the percentage is decoration.

Implemented in `collectors/select_targets.py`, which produces two artefacts:
the working target list, which is git-ignored, and
`data/aggregates/selection_manifest.json`, which is committed. The manifest
records the ranking file name and its SHA-256, the filters applied, the
classification ruleset and its SHA-256, per-rule hit counts and per-sector
totals. It contains no domain names, so a reader can challenge the sampling
without being handed the sample.

Method `[assumption]`:

1. Pin a public ranking (Tranco) by hash. Downloading it is not automated: the
   list is dated and versioned upstream, and pinning a specific file is the
   point.
2. Filter to the ccTLD or region of interest.
3. Classify into sectors using `config/classification.yaml`, matching exact,
   then contains, then suffix, with an `exclude` list per sector. First match
   wins and the winning rule is recorded.
4. Enforce a minimum bucket size at aggregation. Sectors below it are dropped,
   not reported with n=2.

Rule collisions are counted, not resolved silently. A domain matched by rules
from more than one sector is recorded in the manifest along with the colliding
rule identifiers, because config order decides the winner and the loser
otherwise leaves no trace. The first run of the detector found the Polish stem
`gaz` in the energy ruleset capturing `gazeta`, moving newspapers into the
energy sector. Narrowing the token is the fix; reordering the config only moves
the collision somewhere else.

Sector names in `config/classification.yaml` must match the keys in
`scoring/weights.yaml`, or scoring silently falls back to the default horizon.

Known limitation `[inference]`: keyword classification of domain names is crude.
A domain containing `bank` is probably a bank; a bank whose domain contains no
listed token is invisible. For anything published, replace the heuristics with
an authoritative register: supervisory lists for financial entities, health
registers for healthcare, the public-entity register for government.

Known bias `[inference]`: Tranco ranks by resolver traffic, which
overrepresents consumer-facing web properties and underrepresents API
endpoints, B2B services and machine-to-machine infrastructure. Since
machine-to-machine traffic is where long confidentiality horizons concentrate,
this sampling method systematically undercounts the highest-HNDL population.
The note is embedded in the manifest so it travels with the numbers rather than
living in a document nobody opens.

## 3. Passive collection, Modality A

Source: Certificate Transparency via crt.sh.

The two-surface problem, which is the main technical reason this collector is
more than fifty lines: the crt.sh JSON search surface returns log entry
metadata only. It does not return the public key algorithm or the signature
algorithm. Those require fetching the certificate itself and parsing it. A
report that quotes issuer and expiry from CT metadata while implying that key
algorithm was measured has not measured key algorithm.

Per host, the collector keeps the most recently logged leaves, deduplicated by
serial. Parsing every historical entry burns the upstream API without adding
signal about *current* posture.

Operational properties, because the shape of the store determines whether a
rerun is cheap:

- one JSON file per host, so the run is resumable at host granularity
- TTL-based freshness, so a rerun does not re-hit the API
- atomic writes via tmpfile plus `os.replace`, so an interrupted run leaves no torn records
- corrupt or partially written files are treated as absent and rewritten

Sources considered and deferred:

- **Censys / Shodan** `[deferred]`. Both would add data the CT logs do not
  carry, notably observed served chains and non-443 TLS. Deferred from sprint 1
  because the platform API surfaces have changed within the last year and
  writing an untested client against a remembered schema would put unverified
  claims into the repository. To be added with credentials and a live test, not
  from memory.
- **Own CT log tailer** `[deferred]`. Removes the crt.sh dependency and the
  rate-limit ceiling. Correct end state, disproportionate for sprint 1.

## 4. Active probing, Modality B

One TLS 1.3 handshake per allowlisted target offering `X25519MLKEM768`, then
reading the negotiated group.

Client capability gate: OpenSSL 3.5 or later. Below that, the client cannot
offer the group, and a negative result would be a statement about the client.
The probe refuses to run rather than emit that result. This is the single most
common way this test is reported wrong.

HelloRetryRequest detection `[inference]`: inferred from the client writing
ClientHello twice in the `-state` trace. The definitive marker is the special
ServerHello random value from RFC 8446 section 4.1.3, which requires a build
with `enable-ssl-trace`. The heuristic is labelled as an inference in the output
record rather than presented as measured.

What a negotiated group does and does not prove `[inference]`: it proves that
this endpoint, on this connection, agreed to a hybrid key agreement. It does not
prove that every endpoint behind the same name does, that non-browser paths do,
or that anything below TLS does.

## 5. Scoring

See `scoring/weights.yaml`. Three properties matter more than the specific
numbers:

1. Every constant is in config. A reviewer can rerun with their own weights.
2. Every component carries its own provenance label, and the composite inherits
   the weakest one.
3. The sector confidentiality horizon is named as an assumption in the config,
   in the code, and in every output record. It is the load-bearing input, and
   burying it would make the whole model look more measured than it is.

Anchoring to a regulatory milestone rather than a Q-Day forecast is deliberate.
The milestone is a published date. A Q-Day estimate is a forecast, and a
forecast inside an arithmetic model becomes invisible within one slide.

### 5.1 Defect found and fixed: exposure cap saturation

The first version set `horizon_pressure_cap_years: 20` while the longest
configured horizon was 30. Exposure is measured against the milestone, so with
4.43 years still to run, a 30-year horizon yields 25.57 years of exposure and a
25-year horizon yields 20.57. Both exceeded the cap, clamped to 1.0, and
healthcare, defence and government therefore scored identically on a component
carrying weight 0.30. The model stopped discriminating exactly among the
sectors it exists to rank.

Root cause was not the curve shape. It was two independent numbers in one
config that silently had to agree, with nothing checking them. The cap is now
derived from the longest configured horizon by default, so it cannot drift, and
it renormalises as the milestone approaches, which is correct: the same 30-year
horizon buys more exposure every year that passes. A fixed cap is still
accepted, because deliberate saturation is a legitimate analytical choice, but
`validate_config` reports which sectors it collapses, and CI fails on it.

Bottom-end flooring is reported as a warning rather than an error. Sectors whose
horizon is shorter than the distance to the milestone carry no HNDL exposure at
all, so they share a component value by construction. That is a property of the
model, not a defect in it, and the distinction between the two is why the
validator carries severities.

## 6. Rejected options, with rationale kept

**Mass active sweep of third-party estate, nmap or equivalent. Rejected.**
The legal and reputational downside came from the intent, not the technique.
A single handshake is defensible; a sweep carries the connotation of
reconnaissance. "I ran nmap against 500 banks" and "I performed a standard
handshake" describe comparable traffic and opposite optics. NIS2 and financial
sector entities log and monitor, so the realistic outcome is a SOC alert
attached to an IP address attached to a name on a public repository. The
downside is asymmetric and the marginal signal was near zero: PQC KEM adoption
is early, the finding would have been "almost nobody supports hybrid yet", and
that is establishable from a sample without a sweep.

**Custom nmap NSE script for hybrid group detection. Rejected.**
`ssl-enum-ciphers` does not probe hybrid supported_groups out of the box.
Fixing that means parsing key_share, handling codepoints and HelloRetryRequest,
which duplicates what OpenSSL 3.5 does in one line, and what tlsx, SSL Labs and
public PQC scanners already do. It moves effort to where there is no return and
hides the actual differentiator, which is scoring plus provenance plus the
detection layer.

**Batch orchestrator for the active probe. Deferred.**
Rate limiting, resumability, atomic writes and an idempotent per-host store are
the right pattern at scale, and they are implemented for the passive collector
where the target count justifies them. For a dozen allowlisted hosts, an
orchestrator would be architecture as decoration.

## 7. Disclosure enforcement

The scope statement is executable. `collectors/disclosure.py` provides a
structural guard used by every writer, and `tests/lint_disclosure.py` runs the
same guard from the outside over committed files, which catches hand-edited
JSON that never passed through a writer.

Three decisions inside the guard are worth recording, because each one is a
trade-off rather than an obvious choice.

Certificate SHA-256 fingerprints are treated as host identifiers. A fingerprint
resolves back to a domain through the same public CT logs the data came from,
so publishing one undoes the sector aggregation. The cost of this rule showed up
immediately: the selection manifest's file hash had to be renamed from `sha256`
to `file_sha256` to pass. That is the intended cost. A blunt guard whose false
positives cost a rename is preferable to a precise one whose false negatives
cost the premise of the project.

The filename exemption deliberately excludes `.sh`, `.py`, `.md`, `.ai`, `.io`,
`.cd` and `.tv`, all of which are live ccTLDs. Allowing them would create a
blind spot precisely where a domain is most likely to be mistaken for a
filename.

The prose scan strips fenced blocks and inline code spans, because otherwise
every dotted identifier in the documentation is a false positive and the guard
gets switched off within a week. The accepted consequence is that a hostname
hidden inside backticks in a markdown file would pass the prose scan. Structural
JSON output has no such exemption, and that is where collected data actually
lands.

## 8. Endpoint capability resolution

Two questions get conflated in most PQC readiness material. "Should we adopt
ML-KEM" is a policy question. "Can this host negotiate a hybrid group at all" is
an inventory question with a factual answer, and it decides whether a finding is
a crypto-policy ticket or a package-upgrade ticket.

`inventory/pqc_capability.py` answers the second one from a software inventory
export. Three properties matter:

Version comparison is component-wise, not float-based. `3.10.1` is above
`3.5.0`; treating versions as decimals inverts that and misclassifies precisely
the hosts that have already been upgraded. OpenSSL letter releases (`1.1.1w`)
and distribution suffixes (`3.5.0+deb12u2`) parse into ordered components rather
than failing.

Thresholds live in `config/pqc_capability.yaml` and carry provenance. OpenSSL
3.5.0, GnuTLS 3.8.8 and wolfSSL 5.8.0 are `measured` with reference URLs to
their release notes. GnuTLS shipped `X25519MLKEM768` as experimental in 3.8.8
(2024-11-05) following draft-kwiatkowski-tls-ecdhe-mlkem; wolfSSL shipped the
standardised-codepoint hybrid groups in 5.8.0 (2025-05), which is the
interoperable boundary rather than the first appearance of any hybrid group.
NSS and LibreSSL are `null` and resolve to `unknown`: NSS has shipped hybrid PQ
groups but the exact release cutover was not confirmed against a primary source
here, and a wrong threshold silently reclassifies a whole population. BoringSSL
is `not_applicable`, vendored per product.

Capability is a precondition, not behaviour. A capable host can still negotiate
a classical group because of policy, a middlebox or a peer that never offers a
hybrid one. The measurement of what actually happens lives in the Sigma
negotiation rules; this module measures what is possible.

Device identifiers are consumed for counting and never emitted. The disclosure
guard was extended with the identity columns that inventory exports carry
(`DeviceId`, `DeviceName`, `Computer`, `hostname`, `fqdn`, `ip`) and runs over
the payload before it is written.

## 9. Defects found by testing

Recorded because a repository that only shows its successes is a brochure.

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
never be published. Renamed to `file_sha256`. The guard is blunt on purpose and
this is what its false positives cost.

## 10. Open items

- `[verify]` Zeek `ssl.log` codepoint spelling for `0x11EC` on the target sensor build.
- `[verify]` Defender table columns (`DeviceTvmCertificateInfo`, `DeviceTvmSoftwareInventory`) against a live tenant with `getschema`.
- `[verify]` Application Gateway log field naming for the workspace's diagnostics collection mode.
- `[verify]` The active handshake success path cannot be executed here: no OpenSSL 3.5 has been available in any environment used so far. The subprocess call is therefore unverified, but the output parser is now tested against synthetic transcripts (`tests/test_handshake.py`), so a real success result will be read correctly when a 3.5 client is available.
- `[todo]` NSS and LibreSSL capability cutover versions. GnuTLS and wolfSSL verified in sprint 5; NSS/LibreSSL still `null` -> `unknown`.
- `[todo]` Censys client with credentials and a live test.
- `[todo]` Replace `config/classification.yaml` keyword heuristics with authoritative sector registers before any figure is published.
- `[todo]` Declare operator-owned infrastructure under `self` in `config/reference_hosts.yaml`; until then the active modality demonstrates the method against reference implementations only.
