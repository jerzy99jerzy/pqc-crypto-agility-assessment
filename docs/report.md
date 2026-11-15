# PQC Crypto-Agility Assessment: Report

Generated 2026-11-15 from committed aggregates. Host-level data was not read for this report.

## 0. Provenance legend

| Label | Meaning |
|---|---|
| `[measured]` | Read from a certificate, a handshake or a log, without interpretation |
| `[reported]` | Supplied by the party the report is for; fields parsed here, completeness is their claim |
| `[inference]` | Derived from observable proxies |
| `[assumption]` | Chosen by the analyst, defensible but not observed |
| `[speculation]` | Explicitly uncertain, carried through rather than resolved |

A composite value inherits the weakest label of its inputs.

## 1. Selection and denominator

Source ranking `top-1m.csv`, SHA-256 `039d87d66a7ec215...`, 1000 rows in scope after filters `{'suffix': '.pl', 'top_rank': 138507}`. `[measured]`

Classification ruleset `classification.yaml`, SHA-256 `a230c20c96b331cd...`. Unclassified: 861 rows. `[inference]`

| Sector | Selected |
|---|---:|
| government | 47 |
| education | 29 |
| media | 26 |
| retail | 12 |
| telecom | 9 |
| finance | 8 |
| energy | 5 |
| healthcare (below minimum bucket, suppressed downstream) | 2 |
| legal (below minimum bucket, suppressed downstream) | 1 |

**Classification ambiguity** `[measured]`: 4 domain(s) matched rules from more than one sector and were resolved by config order. Colliding rule sets, with counts:

- `energy.contains:oze | media.contains:radio` : 1
- `finance.contains:fundusz | government.suffix:.gov.pl` : 1
- `government.contains:samorzad | media.contains:portal` : 1
- `government.suffix:.gov.pl | media.contains:portal` : 1

**Known sampling bias** `[inference]`: Resolver-traffic rankings overrepresent consumer-facing web properties and underrepresent APIs, B2B services and machine-to-machine endpoints. Long confidentiality horizons concentrate in the underrepresented population, so this sampling systematically undercounts the highest-HNDL assets. Stated here so the limitation travels with the numbers.

## 2. Measured certificate dimensions `[measured]`

Modality: A_passive_public_ct. Generated 2026-08-06T01:51:44.258452+00:00.

| Sector | Hosts | With cert | Quantum-vulnerable key | Valid beyond 2030 | PQC indicators |
|---|---:|---:|---:|---:|---:|
| education | 12 | 3 | 3 (100%) | 0 (0%) | 0 |

Disclosure policy: sector granularity, minimum bucket 1, suppressed: none.

Key algorithm distribution:

- **education**: RSA-2048: 2, RSA-4096: 1

_Certificate dimensions describe the served leaf certificate only. They say nothing about the negotiated TLS key exchange, and therefore nothing about PQC readiness of the key agreement. See README section 'What this assessment will not tell you'._

## 3. HNDL exposure

No scoring output present.

## 4. Active PQC demonstration

No handshake output present. Requires OpenSSL 3.5 or later and hosts declared in `config/reference_hosts.yaml`.

## 5. Endpoint crypto capability

No capability analysis present. Run `pqc-capability --inventory` against a software inventory export to answer the question that gates the plan: on how many hosts is the crypto stack capable of a hybrid key exchange at all.

## 6. What this assessment does not tell you

- Bulk data encryption (volumes, databases, object stores under AES) is not in migration scope: AES-256 keeps 128 bits of strength against Grover.
- At rest, the exposure is the layer of RSA and EC keys that wrap data keys. It is counted from an operator-supplied key management export (pqc-keys), not from certificate data.
- Signing keys carry forgery risk on their own horizon, which the HNDL score does not measure.
- Application-layer cryptography, such as keys compiled into binaries or encryption written by hand in application code, is not observable.
- HSM internals beyond the attributes a key management API exposes, and keys held outside any managed service, are not observable.
- Internal PKI is visible only indirectly, through endpoint certificate inventory in the detection layer.
- Code, embedded libraries and certificates pinned inside applications are not observable.
- The key exchange group a third-party service negotiates is not observable from certificate data. It needs an active handshake, which is not performed against third-party estate.
- A certificate that uses RSA says nothing about whether the same service already negotiates a hybrid group.

## 7. Scope

Third-party estate: public Certificate Transparency data only, no active traffic. Active handshakes: operator-owned infrastructure and declared public reference implementations only, enforced by allowlist in code. Aggregation by sector with a minimum bucket size. No organisation is named next to a vulnerability finding.
