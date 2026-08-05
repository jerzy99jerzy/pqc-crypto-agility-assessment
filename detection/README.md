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
| `spl/tls_key_exchange_inventory.spl` | Numerator and denominator from one filter, so the ratio means something. |
| `spl/x509_vulnerable_key_beyond_milestone.spl` | Which observed certificates have no renewal scheduled before the milestone? |
| `spl/crypto_library_pqc_capability.spl` | Can the fleet's crypto stack negotiate a hybrid group at all? |
| `spl/tls_migration_burndown.spl` | Is the hybrid share moving, and fast enough? |

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
| SPL structural discipline | `[measured]` 4/4 pass `make spl-check`: every search declares its question, its source assumption and its validation status; the milestone is a macro, not a retyped date; and no search filters on `="true"` in a way that would drop the `unknown` state |
| Splunk field names (`zeek:ssl`, `zeek:x509`, package inventory) | `[inference]` from Zeek and Splunk documentation, not run against an indexer |
| Search cost at real telemetry volume | `[unknown]` unmeasured. A correct search that is unaffordable to schedule is not deployable content, and this cannot be answered without a live instance |

Everything marked `[inference]` needs one `getschema` or one sample event
before it goes into a scheduled query. That is a ten-minute job in any real
tenant and it is not a job this repository can do on your behalf.

## Deployment shape

Inventory rules belong in a summary table refreshed daily or weekly, not in an
incident queue. The useful artefact is two numbers over time: sessions or assets
that are PQC-capable, and sessions or assets that are not. Everything else in
this folder is instrumentation for producing those two numbers honestly.


## Why SPL as well as KQL

Two targets, one reason: the buyers who hold detection budgets are split
roughly between Sentinel and Splunk, and content that only runs in one of them
is a partial product. The searches are not translations of each other. Splunk
gets `tstats` against an accelerated data model where that is the affordable
shape, Sentinel gets the KQL idiom, and each carries its own source assumption.

Two things are shared deliberately. The milestone is a macro on the Splunk side
and a parameter in the pipeline, so the date lives in one place per system
rather than being retyped per query. And the version thresholds behind the
capability search come from the same primary sources as
`ananke/inventory/pqc_capability.py`; the search reads them from a lookup so
the SOC number and the assessment number cannot drift apart silently.

The version comparison in the capability search is done on a zero-padded
numeric key rather than by string comparison. `"3.5"` sorts below `"3.10"` as a
string, so a truncated version would be misclassified as not capable. That
exact defect shipped once in the pipeline (F2, sprint 6) and repeating it in
the query language would be careless.

## What is still missing

Every field name here is `[inference]`. Both a Splunk dev instance and an Azure
Sentinel dev tenant are obtainable (T15) and the sequence is deliberate: write
the content first, stand both up once, validate everything in a single session.
Validating piecemeal means writing each query twice.

There is also no backend compile step. Sigma rules parse; nothing yet shows
they convert to a deployable query for a named target via `sigma convert`. A
buyer wants to paste a query, not an intermediate representation.
