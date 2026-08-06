# Rotation cadence as a crypto-agility proxy

Status: proposal, not implemented
Drafted: 2026-08-06
Companion document: `COMPETITORS.md`

Provenance convention: `[measured]` observed or cited from a primary source |
`[inference]` our judgement | `[assumption]` stated, not tested | `[estimate]`
sized, not verified | `[not found]` searched for and not located, which is not
the same as absent

## Thesis

The standard output of a passive certificate assessment is the share of an
estate still using quantum-vulnerable public-key algorithms. That number is a
snapshot of *state*. It is cheap to reproduce from public data, and it is
converging on the same answer everywhere.

`[measured, verified 2026-08-06]` It converges because the ecosystem gives it no
room to vary. Public certificate authorities have issued no ML-DSA roots that
chain into the Mozilla, Apple, Microsoft or Chrome trust stores, the CA/Browser
Forum has no merged baseline requirement permitting ML-DSA in publicly trusted
certificates, and no major browser negotiates ML-DSA for the server certificate
by default. A ballot to permit it is being drafted, so this will change, but it
has not changed yet.

The quantity that actually predicts whether an organisation meets the 2030
milestone is therefore not its current algorithm mix. It is whether it can
change algorithms at all. That capability leaves an observable trace in
Certificate Transparency: the interval between successive issuances for the same
name.

`[inference]` An estate that reissues on a short automated cycle has a working
change mechanism and can migrate whatever it is running today. An estate on
manual renewals does not have one, and its algorithm mix is irrelevant until it
builds one. Two organisations with identical RSA-2048 percentages can sit on
opposite sides of the 2030 deadline for this reason alone.

## Position against existing tooling

`[inference]` Scanners observe the endpoint as it is now. Cadence is visible
only in the issuance history, which lives in the CT log rather than in the
handshake, so a tool that reads CT for state discards the timestamps that carry
the signal.

`[measured, reviewed 2026-08-06]` A first-pass competitor review is recorded in
`COMPETITORS.md`. It found the collection layer to be commodity, the ethics and
scope-guard posture to be independently implemented elsewhere, and the headline
passive finding to be already published from Certificate Transparency data.

`[not found]` That same pass surfaced no tool or paper reporting issuance
cadence as a migration-capability signal for third-party estates. Four search
queries are not proof of absence. In client-facing material the claim is phrased
as "we have not found", never as "nobody does this". Subject to that wording,
this is the only element of the project's stated differentiation that the review
left standing alongside the detection layer.

## Definition

For each registrable domain in scope, over a fixed observation window:

- **Issuance interval.** Median days between consecutive CT entries for the same
  subject name, precertificates excluded so that a single issuance is not
  counted twice.
- **Cadence class.** Derived band, expressed as a fraction of the maximum
  validity permitted at the time of issuance rather than as an absolute number of
  days. See the regulatory section below for why the absolute form breaks.
- **Dispersion.** Variance of the interval. Low variance at a short interval is
  the signature of automation; high variance is the signature of humans.
- **Coverage.** Share of names in the estate falling in each class, reported per
  entity as well as per certificate.

Output is a capability band per entity, not a score, and it is reported
alongside the algorithm mix rather than folded into it.

## Regulatory context that reshapes the metric

`[measured, verified 2026-08-06]` Maximum validity for publicly trusted TLS
certificates is being cut on a published schedule: 200 days from March 2026,
100 days from March 2027, 47 days from March 2029. Let's Encrypt additionally
made an opt-in six-day profile generally available in January 2026 and has
signalled an intent to shorten its default lifetime over the coming years.

Two consequences, both load-bearing:

**Short interval will stop discriminating.** Once the ceiling forces everyone
below 100 days, a short median interval no longer distinguishes a capable estate
from a compliant one. The durable signal is not the interval itself but the
dispersion around it and the presence of gaps, which is where manual processes
stay visible.

**The schedule is a natural experiment.** `[inference]` Each step down is a
forced change event with a known date. An estate that cannot automate will show
it at the boundary: late reissuance, expiry gaps, a scramble in the weeks before
each cut-off. Behaviour across the March 2026 step is already in the log, which
makes it the cheapest available evidence of whether an organisation's change
mechanism works. It is observable only if historical records are retained.

## What this metric does not say

- `[measured]` CT proves issuance, not deployment. A short interval shows that a
  certificate was minted, not that the endpoint serves it.
- Cadence indicates a working change mechanism for publicly trusted TLS
  certificates specifically. It says nothing about code-signing keys, embedded
  device certificates, internal PKI, or cryptography at rest.
- `[assumption]` Bands cannot be fixed against a single lifetime, because the
  ceiling moves in March 2026, 2027 and 2029. Expressed absolutely, the same
  estate appears to improve without changing anything.
- Absence of reissuance inside the window is ambiguous: it can mean a stagnant
  estate, or a long-lived certificate issued before the window opened. The two
  are not separable without extending the window, and are reported as one class
  rather than silently collapsed into "manual".
- `[inference]` A short cadence achieved by a CDN or hosting provider on the
  customer's behalf measures the provider's automation, not the customer's. The
  distinction matters for any estate largely fronted by a third party and is not
  resolvable from CT alone.

## Dependency this creates on collection

The metric requires historical issuance records. A collection run filtered to
currently-valid certificates discards exactly the rows the metric consumes.
Retention scope therefore has to be decided **before** the first real run, or
the run has to be repeated.

## Open questions

1. Observation window length, traded off against crt.sh query cost and against
   the ambiguity of the stagnant class.
2. Whether cadence enters the HNDL score as an input or stays a parallel axis.
   `[inference]` Parallel is more defensible: cadence is capability, HNDL is
   exposure, and averaging them hides the case that matters most, which is long
   exposure combined with no change mechanism.
3. Calibration of the bands against an estate whose automation is known, which
   requires a first-party or reference target set.
