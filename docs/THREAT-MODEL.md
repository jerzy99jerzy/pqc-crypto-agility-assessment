# Threat model

Project codename: ANANKE.

Version 1.0, 2026-08-05.

`docs/METHODOLOGY.md` covers what may be claimed from the data.
`docs/MECHANISMS.md` covers how each mechanism works.
This document covers what an adversary does to those mechanisms.

The framing is deliberately narrow. This is a local command-line tool with no
server, no authentication and no multi-tenancy, so the interesting attacks are
not about access. They are about making the tool break its own two promises, or
making the number it produces wrong in a direction somebody benefits from.

## Assets

1. **The scope promise.** No packet reaches a third party's infrastructure; no
   host identifier reaches committed output. This is the asset that makes the
   project publishable at all.
2. **Measurement integrity.** The reported number and its provenance label. A
   report that overstates PQC readiness is worse than no report, because it
   retires a risk that is still live.
3. **The operator's own estate data.** Since v0.9.0 the tool ingests client
   certificates, which are not secret but are commercially sensitive.

## Trust boundaries

| Boundary | What crosses it | Control |
| --- | --- | --- |
| B1, Certificate Transparency | JSON metadata and certificate bytes from a public log anyone can write to | `parse_certificate` never raises; errors are recorded per certificate rather than aborting a run |
| B2, offline estate | arbitrary bytes from a directory a third party assembled | same parser; host identity taken from the signed subject, never from the filename |
| B3, configuration | `targets.yaml`, `weights.yaml`, allowlist | `--validate-config`; the allowlist is the only thing that authorises an active probe |
| B4, committed output | sector aggregates, generated report, documentation prose | `assert_no_host_identifiers`, `assert_bucket_sizes`, prose lint in CI |

## Adversaries and what they attempt

### A1. An adversary who wants their host named in somebody else's report

The cheapest attack on this project is not against the operator; it is against a
third party who would rather not appear. Reverse it and the attack becomes: get
a host identifier into a published aggregate, so the publisher is the one who
disclosed it.

Mechanism: put host-shaped text where the guard does not look. A certificate
subject, a SAN entry, an error string carrying a hostname, a filename in an
offline dump, a CN with an underscore glued to the front.

Status: the underscore variant worked until v0.8.0 and passed both guards
silently. That is the reference example for this class. The guard now writes its
boundaries by hand rather than relying on `\b`, and every fix carries a
regression test, but the honest position is that this class is not closed. It is
the first place to look when reviewing.

Residual risk: a host identifier in a field the guard walks but does not
recognise as host-shaped, for example an internationalised domain in punycode
form, or a bare IPv6 literal. Documented rather than fixed.

### A2. An adversary who poisons a public log

Certificate Transparency accepts submissions from anyone with a trusted CA
signature, and the tool ranks nothing on its own. An adversary who wants a
sector to look better or worse than it is can submit certificates that skew a
bucket.

Control: none, and this is a design position rather than an oversight. The
sample is public, the method is documented and the aggregate says how many hosts
it counted, so a reader can reproduce it. Sector buckets below the minimum size
are suppressed, which incidentally raises the cost of skewing a small sector to
the cost of skewing a large one.

Residual risk: real. A sufficiently motivated party can move a sector-level
percentage. The mitigation is disclosure of method, not prevention.

### A3. A client who supplies a convenient inventory

New in v0.9.0 and the sharpest of the three, because this adversary is paying.
An operator who wants a clean report hands over a directory containing their
modern certificates and omits the estate that would fail. Nothing in the files
is false; the set is simply not the estate.

Control: the provenance label. Data from this path is `reported`, never
`measured`, and the label sits on the set rather than on the field, because each
individual certificate genuinely is parsed here. The aggregate carries
`first_party_estate: true` and the modality that produced it, so a reader can
see which regime the number came from.

Residual risk: this is a control on honesty of reporting, not on the input.
There is no way to verify a dump is complete from the dump. An engagement that
needs assurance needs the passive layer run in parallel against the same
operator's public estate, and a discrepancy between the two is itself a
finding. That comparison is not implemented.

### A4. An operator who wants the tool to touch a target

The active modality is the only path that emits packets to a named host. The
attack is social rather than technical: talk the operator into adding a
third-party host to the allowlist and describing it as `reference`.

Control: the allowlist is committed, so the change is visible in history and in
review. The distinction between `self` and `reference` is documented in
`README.md` with the reasoning, and reference hosts are limited to
implementations that expect billions of connections.

Residual risk: a human decision, unenforceable in code. Recorded here so it is
at least a visible one.

### A5. Silent metric distortion

Not an adversary, but it belongs in this document because the consequence
matches one. An unrecognised key or signature OID resolving to `False` rather
than `None` reports a vulnerable certificate as quantum-safe. Nothing fails, no
error is logged, and the number moves in the flattering direction.

This shipped once, was found in review, and is fixed with the tri-state
convention documented in `ananke/collectors/certparse.py`. It is listed as a
security defect rather than a bug because the product of this pipeline is a
number that somebody will budget against. Any new input path, including the
inventory import in T11, must be reviewed against this specific failure mode.

## What this threat model does not cover

- The correctness of the detection content in `detection/`. Rules are validated
  for syntax and, where possible, against real telemetry; their evasion
  resistance is not modelled.
- Supply chain of the Python dependencies.
- The machine the tool runs on. If it is compromised, none of the above matters.
- Physical or network-level attacks against Certificate Transparency operators.
