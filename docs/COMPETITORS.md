# Competitive landscape

Review date: 2026-08-06, links re-checked 2026-11-15
Status: first pass, four targeted web searches, not a systematic review
Companion document: `ROTATION-CADENCE.md`

Provenance: `[measured]` applies to the existence and self-described
capabilities of the named projects, taken from their own documentation. It does
not apply to the completeness of this list, nor to whether any of these tools
work as advertised. `[not found]` means searched for and not located, which is
not the same as absent.

The first pass did not record links. Entries with a link below were located
again on 2026-11-15; entries without one stand as `[reported]` from the first
pass. Nothing here has been executed or evaluated hands-on.

## Why this file exists

`docs/` previously asserted that the project's differentiators were the
repeatable method, the provenance discipline and the ethics posture. That
assertion was made without a competitor review. This file is the review, and it
does not support the assertion in that form.

## Layer 1: commercial cryptographic inventory and CBOM platforms

`[reported]` A consolidated category rather than a set of individual
competitors. Published vendor comparisons cover CBOM Secure, IBM, Keyfactor,
SandboxAQ and CryptoNext, with discovery methods spanning passive network
capture, agent-based host scanning and static source analysis. AppViewX ships a
PQC assessment tool that emits a CycloneDX CBOM and a readiness score from code,
dependencies, configuration and certificates. QryptoCyber positions on
inventory completion in weeks and can run through agents the customer has
already deployed.

**Implication.** The collection layer is a commodity with funded incumbents. Any
positioning that rests on "we can inventory your cryptography" competes directly
with product teams.

## Layer 2: advisory

`[reported]` Accenture, Deloitte, EY, PwC, KPMG, Wipro, Capgemini, NTT Data and
DXC all have quantum-safe practices at varying maturity. Specialist
consultancies sell the exact shape of MVP-B: cryptographic discovery and
inventory, followed by a gap analysis and a phased migration roadmap.

**Implication.** This is the closest competitor to the productized assessment
path, and the one with existing board-level access. A partnership with a
consultancy would make it both the distribution channel and the substitute
good.

## Layer 3: open source

- [`anvilsecure/pqcscan`](https://github.com/anvilsecure/pqcscan) (Rust). Scans
  SSH and TLS servers for stated PQC support, JSON results, HTML report.
- [`csnp/cryptoscan`](https://github.com/csnp/cryptoscan). Source-code
  cryptographic discovery with a migration readiness score, part of a wider
  quantum-readiness toolkit.
- [`cyberjez/PQC-Scanner`](https://github.com/cyberjez/PQC-Scanner).
  Internal-network TLS certificate scanning with chain inspection, PQC OID
  detection and hybrid key-exchange identification.
- [`epap011/Crypto-Scanner-PQC`](https://github.com/epap011/Crypto-Scanner-PQC).
  Academic coursework, low relevance.

Two projects overlap directly with this repository's architecture:

- [`jimbo111/open-quantum-secure`](https://github.com/jimbo111/open-quantum-secure)
  orchestrates engines including `ct-lookup`, `zeek-log` and `suricata-log`
  alongside code scanning and TLS/SSH probes, with CycloneDX CBOM output. That is
  Certificate Transparency plus network telemetry in one tool, the combination
  this project treats as its shape.
- [`quantakrypto/pqc-tools`](https://github.com/quantakrypto/pqc-tools)
  includes qProbe, which actively probes endpoints the operator owns for
  X25519MLKEM768 support, gated behind an ownership attestation, with a
  published threat model and a stated principle of reporting without modifying.

All six repositories were reachable on 2026-11-15; their descriptions above are
from the first pass.

**Implication, and the important one.** The ethics and scope-guard posture is
not a differentiator. Another project reached the same design independently and
shipped it with an ownership attestation gate. The posture remains correct and
worth keeping. It is not a moat.

## Layer 4: published research on passive and certificate posture

`[reported]` The first pass recorded a 2026 paper analysing a CT-derived TLS
dataset for one national estate, with RSA a large majority of public keys. Its
citation was not recorded, and two searches on 2026-11-15 did not locate it, so
its figures are not repeated here.

Two published measurements were located for this revision:

- [Dubey and Varshney, arXiv 2606.16473](https://arxiv.org/abs/2606.16473)
  measure 32,011 domains through TLS handshakes rather than CT: certificate
  signatures RSA 56.9% and ECDSA 43.1%, with no post-quantum or hybrid
  certificate observed.
- [Ibrahim, Ajith and Haroon, ePrint 2026/834](https://eprint.iacr.org/2026/834)
  detect post-quantum and hybrid TLS deployments through raw TLS record
  inspection.

**Implication.** The headline passive finding, a public-key population that is
almost entirely RSA and ECC with no post-quantum certificates, is already
published. A report cannot be built on it.

## Layer 5: SOC-native detection content

`[not found, which is weak evidence of absence]` A keyword search surfaced no
PQC-specific detection rules in SigmaHQ and no public Sentinel content pack for
vulnerable cryptography. This has not been verified by grepping the rule
repository, which is the check that would settle it.

The space is being occupied from the vendor side rather than the content side.
Palo Alto NGFWs
[detect, log and optionally block](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/decryption/post-quantum-cryptography-detection-and-control)
TLS 1.3 sessions using post-quantum and hybrid algorithms, driven from
decryption policy.

**Implication.** The gap is real but narrower than assumed. In an estate with a
capable NGFW, a handshake-based rule duplicates a product feature. The
defensible content is what the network vendor does not give away:
inventory-based rules over software and library versions, and correlation across
sources.

## What survives this review

1. **The detection layer**, narrowed as above. Still the thinnest-served area
   and still the stated wedge.
2. **Rotation cadence as a migration-capability proxy**, specified in
   `ROTATION-CADENCE.md`. `[not found]` No tool or paper in this pass reports
   issuance cadence as a capability signal for third-party estates. This is the
   only unclaimed element the review located, which raises its weight relative
   to everything else in the backlog.

## What does not survive

- "The pipeline and provenance discipline are the differentiator." The pipeline
  shape exists in open source, including the CT and Zeek combination.
- "The ethics posture is a commercial asset others lack." Shipped elsewhere.
- "The finding is trivial but ours is the method." The finding is published.

## Open items

- Grep SigmaHQ and the Sentinel content hub directly, to convert Layer 5 from
  `[not found]` to a measured statement.
- Install and run `open-quantum-secure` and `pqcscan` against a reference target
  to establish what they produce, rather than what their READMEs claim.
- Re-locate the CT-derived national-estate paper from the first pass, or drop
  the entry.
- Positioning material kept outside this repository should cite this file
  rather than assert uniqueness.
