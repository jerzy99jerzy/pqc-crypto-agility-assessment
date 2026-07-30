# PQC Crypto-Agility Assessment

> Certificate dimensions come from public data. PQC readiness is demonstrated
> actively only against own and reference infrastructure. Third-party estate is
> never touched actively.

## Thesis

The EU deadline of 2026-12-31 for initial national PQC roadmaps is five months
out. The bottleneck in that migration is not cryptography. It is inventory:
identifying every place where vulnerable cryptography is in use. That is a data
engineering and telemetry problem, not a lattice problem.

So this repository does not sell a finding. "X% of domains in sector Y still
serve RSA" is trivial to produce and trivial to reproduce. What is not trivial
is a repeatable pipeline, an explicit provenance layer, and a detection layer
that puts the result in front of a SOC in language it already uses.

## Regulatory anchors `[measured]`

| Date | Event |
|---|---|
| 2024-04-11 | Commission Recommendation (EU) 2024/1101 on a coordinated implementation roadmap for the transition to PQC |
| 2024-08 | NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) finalised |
| 2025-06-23 | Member States publish the Coordinated Implementation Roadmap |
| 2026-12-31 | Initial national roadmaps and first steps: identification, awareness |
| 2030-12-31 | High-risk use cases migrated; quantum-safe upgrades as default |
| 2035-12-31 | Full transition |

The 2030 milestone carries the sharpest formulation: for high-risk use cases,
quantum-vulnerable public-key mechanisms must not be used on their own beyond
the end of 2030. Risk holders in scope: NIS2 entities, financial sector under
DORA.

Reference hybrid group: `X25519MLKEM768`, IANA codepoint `0x11EC`, naming per
RFC 9794. Default in OpenSSL 3.5 (LTS through April 2030). PQC algorithm
identifiers in X.509 per RFC 9881 (ML-DSA) and RFC 9935 (ML-KEM).

## Modalities

The collection design is split cleanly, and the split is enforced in code and
in directory layout rather than in prose.

**Modality A, passive, third-party estate.** Certificate Transparency via
crt.sh. Zero packets toward any target host. Measured dimensions: public key
algorithm and parameter, signature algorithm, validity window, whether validity
outlives the 2030 milestone, PQC algorithm identifiers where present. Output is
aggregated by sector only, with a minimum bucket size enforced at aggregation
time. No organisation name is ever emitted next to a vulnerability label.

**Modality B, active, own and reference infrastructure only.** One TLS 1.3
handshake per target offering `X25519MLKEM768`, reading back the negotiated
group and inferring HelloRetryRequest. Targets must appear in an allowlist file
under `self` or `reference`; `active/handshake_demo.py` refuses anything else
before opening a socket. Reference hosts are public implementations serving
internet-scale traffic, used as positive controls for the method itself.

**Modality rejected: mass active sweep of third-party estate.** Rationale kept
in `docs/methodology.md`. Short version: a single handshake and an nmap run
generate comparable traffic and carry opposite optics, the marginal signal was
near zero, and the downside was asymmetric.

## Provenance convention

Three labels, used in code, in output records and in the report:

- `[measured]` data read from a certificate, a handshake or a log, without interpretation
- `[inference]` risk classification derived from observable proxies
- `[speculation]` explicitly uncertain, carried through rather than resolved

A composite value inherits the weakest label of its inputs. The HNDL score is
therefore an inference, not a measurement, and says so in its own output.

Ambivalent signals stay open. Where a result could be a collection artefact or
a real change in posture, the record says so instead of picking the tidier
reading.

## HNDL scoring

Built only from observable proxies, because no data classification is available
and pretending otherwise would be the most consequential lie in the artefact.

Inputs: certificate key algorithm `[measured]`, signature algorithm
`[measured]`, validity window `[measured]`, PQC indicators where observable
`[measured]`, and sector confidentiality horizon `[assumption]`.

Output: years of exposure projected onto the 2030 milestone, plus a weighted
composite with per-component contributions so the number can be argued with.

All weights, horizons and thresholds live in `scoring/weights.yaml`. If you find
one hardcoded in `scoring/hndl_score.py`, that is a bug. The sector
confidentiality horizon is the load-bearing assumption of the entire model and
is labelled as such in the config, in the code and in every output record.

The saturation cap for the exposure term is derived from the longest configured
horizon rather than set independently, because those two numbers silently had
to agree and did not: a fixed cap of 20 years against a 30-year horizon
collapsed healthcare, defence and government onto an identical score on a
component carrying weight 0.30. `make validate` now fails on that class of
config drift, and CI runs it.

No Q-Day estimate enters the arithmetic. The model is anchored to a regulatory
milestone, which is observable, rather than to a forecast, which is not.

## Detection layer

Sigma rules and KQL queries that surface vulnerable cryptography in enterprise
telemetry: TLS handshake logs, Microsoft Sentinel and Defender tables, crypto
library inventory, Key Vault key material. See `detection/README.md`, which
includes an explicit validation-status table separating what was verified
locally from what was taken from vendor documentation.

## What this assessment will not tell you

Stated up front, because the gap between what a passive assessment measures and
what a migration programme needs is where most vendor content quietly lives.

- It does not see cryptography at rest.
- It does not see HSMs.
- It does not see internal PKI, except indirectly through endpoint certificate inventory in the detection layer.
- It does not see code, embedded libraries, or pinned certificates in applications.
- It does not see the negotiated key exchange group of third-party services. PQC readiness of key agreement is not observable from certificate data. It requires an active handshake, which this project does not perform against third-party estate.
- A certificate that uses RSA says nothing about whether that service already negotiates a hybrid group. These are different layers and conflating them is the most common error in this space.

## Ethics and scope statement

Every rule below is enforced by code, and the enforcement runs in CI. A scope
statement that lives only in a README is a scope statement that survives until
the first inconvenient deadline.

- Third-party estate: public data only, Certificate Transparency and equivalent public sources. No active traffic, no scanning, no enumeration.
- Active handshakes: own infrastructure and public reference implementations only, enforced by allowlist in `active/handshake_demo.py`, which refuses an undeclared target before opening a socket. One handshake per target.
- A single handshake to a documented reference implementation is not reconnaissance. It is the same connection a browser makes, made once, on purpose, with the result written down.
- Aggregation by sector, minimum bucket size enforced by `collectors/disclosure.py`. Buckets below the threshold are dropped, not reported with n=1.
- No organisation is named next to a vulnerability finding. `assert_no_host_identifiers` rejects forbidden keys, hostname-shaped strings and certificate fingerprints in anything written to `data/aggregates/` or `docs/`.
- Host-level raw data stays in `data/raw/`, which is git-ignored. Only sector aggregates are committed.
- Target lists are not committed. `config/targets.yaml` is git-ignored, and `tests/lint_disclosure.py` fails the build if it ever becomes tracked.

Certificate SHA-256 fingerprints are treated as host identifiers, not as
metadata. A fingerprint resolves back to a domain through the same public CT
logs the data came from, so publishing one re-identifies the host that the
sector aggregation was supposed to protect.

## Layout

```
pqc-crypto-agility-assessment/
├── collectors/          # Modality A: passive, third-party, public data only
│   ├── crtsh.py         #   CT client, rate limited, backoff, retry
│   ├── certparse.py     #   X.509 dimension extraction, PQC OID aware
│   ├── store.py         #   idempotent per-host store, atomic writes
│   ├── disclosure.py    #   scope statement as an executable guard
│   ├── select_targets.py#   ranking -> targets + committed selection manifest
│   └── passive_cert.py  #   CLI: collect, then aggregate to sector level
├── active/
│   └── handshake_demo.py# Modality B: allowlisted targets only, preflight gated
├── scoring/
│   ├── hndl_score.py    #   scoring engine, no hardcoded constants
│   └── weights.yaml     #   weights, sector horizons, thresholds, assumptions
├── inventory/
│   └── pqc_capability.py#   software inventory -> capability verdicts, version aware
├── reporting/
│   └── build_report.py  #   aggregates -> docs/report.md, cannot read raw data
├── detection/
│   ├── sigma/           #   Zeek and Windows inventory rules
│   └── kql/             #   Defender, Sentinel, Resource Graph queries
├── config/
│   ├── targets.example.yaml
│   ├── classification.yaml   # sector rules, hashed into the manifest
│   ├── pqc_capability.yaml   # library thresholds, provenance-labelled
│   └── reference_hosts.yaml  # active-probe allowlist
├── data/
│   ├── raw/             #   host level, git-ignored
│   └── aggregates/      #   sector level, committed
├── docs/
│   ├── methodology.md
│   └── report.md        #   generated
├── tests/
│   ├── test_pipeline.py
│   ├── test_sprint2.py
│   ├── test_collection.py
│   ├── test_capability.py
│   ├── validate_sigma.py
│   └── lint_disclosure.py
└── .github/workflows/ci.yml
```

The separation between `collectors/` and `active/` is load bearing. Targets are
never mixed between the two.

## Quickstart

```bash
pip install -r requirements.txt

# 1. selection: pin a public ranking, record how the sample was drawn
make select RANKING=tranco_2026_07.csv SUFFIX=.pl TOP=10000

# 2. passive collection and scoring
make collect
make score

# 3. endpoint capability from a software inventory export
make capability INVENTORY=defender_software_export.csv

# 4. report, rendered only from committed aggregates
make report

# 5. active probe: requires OpenSSL >= 3.5, allowlisted hosts only
openssl version
make handshake

# everything CI runs: tests, Sigma structure, config validation, disclosure lint
make verify
```

The active probe refuses to run on OpenSSL below 3.5. A negative result from an
older client would measure the client rather than the server, and that
misattribution is the most likely failure mode of this class of test.

## Status

Sprint 1: passive collection, scoring engine, detection rule pack, provenance
plumbing.

Sprint 2: sampling with a hashed, auditable selection manifest and rule
collision detection; the exposure-cap fix described above; the scope statement
turned into an executable guard with its own lint; report generation; CI.

Sprint 3: test coverage for the collection transport and its failure modes;
endpoint capability resolution with real semantic version comparison, replacing
the bucket the KQL query could not resolve; capability section in the report.

Sprint 4: handshake output parser split from the subprocess call and tested
against synthetic transcripts, closing the largest untested surface without a
3.5 client; optional real-transcript capture for audit; `TODO.md`, `LICENSE`,
`CONTRIBUTING.md`; disclosure lint widened to the root prose files.

Open items live in `TODO.md`, each with a status, a blocker where applicable,
and an acceptance test.
