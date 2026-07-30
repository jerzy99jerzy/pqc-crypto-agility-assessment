# Detection layer

PQC migration is usually written in the language of compliance. A SOC does not
consume compliance language. These rules exist to translate "we must migrate to
post-quantum cryptography by 2030" into three things a detection engineer can
act on: a counted inventory, a capability gate, and a trend line.

None of these are alerts. Routing an inventory rule to an analyst queue is a
deployment error, not a tuning problem.

## What each rule answers

| Rule | Question |
|---|---|
| `zeek_tls_classical_only_key_exchange.yml` | How many external TLS sessions still use classical-only key agreement? (denominator) |
| `zeek_tls_pqc_hybrid_negotiated.yml` | How many already use a hybrid group? (numerator) |
| `zeek_x509_vulnerable_key_beyond_2030.yml` | Which observed certificates are already past the regulatory milestone? |
| `win_schannel_tls_negotiation_inventory.yml` | What does crypto posture look like on hosts the network sensor never sees? |
| `mde_certificate_inventory_beyond_2030.kql` | Same question for the endpoint certificate store, including internal PKI. |
| `mde_crypto_library_pqc_capability.kql` | On how many hosts is the crypto stack even capable of PQC? |
| `sentinel_appgw_tls_migration_burndown.kql` | Trend at the public entry point. |
| `arg_keyvault_key_inventory.kql` | Which stored asymmetric keys outlive the milestone, and which have no rotation plan at all? |

## Validation status

Stated plainly, because a rule pack that implies field validation it does not
have is worse than no rule pack.

| Artefact | Status |
|---|---|
| Sigma rule structure | `[measured]` 4/4 parsed by pySigma `SigmaCollection.load_ruleset` (`make sigma-check`). The full `sigma check` validator set was not run: its tag validator pulls MITRE D3FEND data over the network. One caught defect worth recording: the `\|gte` modifier is numeric-only, so the Zeek x509 expiry comparison is expressed as an epoch value rather than an ISO date. |
| Zeek `ssl.log` / `x509.log` field names | `[inference]` from Zeek documentation, not from a live sensor in this environment |
| Zeek codepoint spelling for 0x11EC | `[inference]` build-dependent, both named and `unknown-4588` forms matched |
| Schannel 36880 field names | `[inference]` from Microsoft documentation; event is disabled by default |
| `DeviceTvmCertificateInfo` / `DeviceTvmSoftwareInventory` columns | `[inference]` from documentation, not run against a tenant here |
| Application Gateway log field suffixes | `[inference]` differs between diagnostics collection modes |
| Azure Resource Graph key properties | `[inference]` from the ARM representation |

Everything marked `[inference]` needs one `getschema` or one sample event
before it goes into a scheduled query. That is a ten-minute job in any real
tenant and it is not a job this repository can do on your behalf.

## Deployment shape

Inventory rules belong in a summary table refreshed daily or weekly, not in an
incident queue. The useful artefact is two numbers over time: sessions or assets
that are PQC-capable, and sessions or assets that are not. Everything else in
this folder is instrumentation for producing those two numbers honestly.
