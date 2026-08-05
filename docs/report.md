# PQC Crypto-Agility Assessment: Report

Generated 2026-08-05 from committed aggregates. Host-level data was not read by this generator and is not available to it.

## 0. Provenance legend

| Label | Meaning |
|---|---|
| `[measured]` | Read from a certificate, a handshake or a log, without interpretation |
| `[inference]` | Derived from observable proxies |
| `[assumption]` | Chosen by the analyst, defensible but not observed |
| `[speculation]` | Explicitly uncertain, carried through rather than resolved |

A composite value inherits the weakest label of its inputs.

## 1. Selection and denominator

**No selection manifest present.** No population figure is reported in this run, because a percentage without a stated denominator is not a finding. Run `collectors/select_targets.py` against a pinned public ranking to generate one.

## 2. Measured certificate dimensions `[measured]`

Modality: D_first_party_offline. Generated 2026-08-05T10:25:53.132864+00:00.

| Sector | Hosts | With cert | Quantum-vulnerable key | Valid beyond 2030 | PQC indicators |
|---|---:|---:|---:|---:|---:|
| logistics | 34 | 34 | 34 (100%) | 14 (41%) | 0 |

Disclosure policy: sector granularity, minimum bucket 1, suppressed: none.

Key algorithm distribution:

- **logistics**: EC-secp256r1: 9, RSA-2048: 24, RSA-4096: 1

_Certificate dimensions describe the served leaf certificate only. They say nothing about the negotiated TLS key exchange, and therefore nothing about PQC readiness of the key agreement. See README section 'What this assessment will not tell you'._

## 3. HNDL exposure `[inference]`

Model version 1.1. Horizon pressure cap 25.59y (derived).

| Sector | n | Exposure beyond milestone | Mean score | Bands |
|---|---:|---:|---:|---|
| logistics | 34 | 0.59y | 0.5949 | elevated: 20, moderate: 14 |

_Certificate dimensions are measured. Sector confidentiality horizon is an assumption stated in scoring/weights.yaml. The composite score is an inference built from both and inherits the weaker label._

Model configuration notes, reproduced rather than hidden:

- **warning**: horizon_pressure floors at zero for: marketing, media. Expected where the horizon is shorter than the distance to the milestone: those sectors carry no HNDL exposure at all. They are not distinguishable from each other on this component, by construction.

## 4. Active PQC demonstration

No handshake output present. Requires OpenSSL 3.5 or later and hosts declared in `config/reference_hosts.yaml`.

## 5. Endpoint crypto capability

No capability analysis present. Run `inventory/pqc_capability.py` against a software inventory export to answer the question that gates the plan: on how many hosts is the crypto stack capable of a hybrid key exchange at all.

## 6. What this assessment does not tell you

- Cryptography at rest.
- HSMs.
- Internal PKI, except indirectly through endpoint certificate inventory in the detection layer.
- Code, embedded libraries, pinned certificates inside applications.
- The negotiated key exchange group of third-party services. That is not observable from certificate data and would require an active handshake, which is not performed against third-party estate.

A certificate using RSA says nothing about whether the same service already negotiates a hybrid group. Different layers. Conflating them is the most common error in this space.

## 7. Scope

Third-party estate: public Certificate Transparency data only, no active traffic. Active handshakes: operator-owned infrastructure and declared public reference implementations only, enforced by allowlist in code. Aggregation by sector with a minimum bucket size. No organisation is named next to a vulnerability finding.
