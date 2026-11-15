# Threat model

Project codename: ANANKE.

Version 2.1, 2026-11-15. Version 2.0 (2026-08-05) re-probed every documented
residual risk against the code. This revision corrects the two residuals that
later releases closed, IPv6 under A1 and the missing cross-check under A3,
against the tests that pin them, records two findings from probes run for this
revision under A1 and A5, and puts the adversaries in order. The other
residuals were not re-probed.

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
| B4, committed output | sector aggregates, generated report, documentation prose | `assert_no_host_identifiers`, `assert_bucket_sizes`, prose scan in CI; citation hosts are admitted in prose only |
| B5, command line | `--sector`, `--milestone`, `--pem-dir`, `--min-bucket`, paths | sector shape-validated at source and re-checked at aggregation; milestone parsed as a date; paths never derived from data; the bucket threshold is not reconciled between selection and aggregation (T19) |
| B6, chart data path | date pairs read from the raw store by the HTML report path | the one sanctioned raw-store read outside collection; fields restricted to `not_before`/`not_after`; embedded for first-party estates only; output re-scanned by the guard |

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
silently. It is the reference example for this class. The guard now writes its
boundaries by hand rather than relying on `\b`, and every fix carries a
regression test, but this class is not closed. It is the first place to look
when reviewing.

Residual risk. Version 2.0 found punycode IDNs (`xn--bank-8qa.pl`), URLs with
credentials, e-mail local parts, uppercase hosts and trailing-dot FQDNs caught,
and IPv6 open. IPv6 literals, bare or bracketed, were closed in 0.14.0 (T14),
and byte-string values that bypassed the walk were closed in the same release.
Open, found for this revision: a certificate fingerprint is caught by field
name only. Under the `sha256` key it fails; the same 64 hex characters under any
other key, or inside a free-text string, pass (probed 2026-11-15, T25). A
fingerprint resolves to a host through CT, so this is an A1 path.

Sprint 10 added a variant that had already shipped: dictionary *keys*. The
sector label supplied on the command line becomes a key in the committed
aggregate, and the guard's value walk never sees keys, so
`--sector "acme-bank.pl production"` published an organisation name. Sector
labels are now shape-validated at the source (a plain categorical token, no
dots) and independently re-checked at aggregation, so a future source that
forgets the first check still fails at the second. The same channel carried a
second payload: markup in the label was stored cross-site scripting waiting for
an HTML renderer, refused by the same validation.

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

New in v0.9.0, and the sharpest of the set, because this adversary is paying. An
operator who wants a clean report hands over a directory containing their
modern certificates and omits the estate that would fail. Nothing in the files
is false; the set is simply not the estate.

Control: two, since 0.12.0. The provenance label: data from this path is
`reported`, never `measured`, and the label sits on the set rather than on the
field, because each certificate genuinely is parsed here. The aggregate carries
`first_party_estate: true` and the modality that produced it. And
`pqc-crosscheck`: the passive layer run against the same operator's public
estate, where a publicly logged certificate missing from the dump is counted as
a finding.

Residual risk: the cross-check is asymmetric by design, so a host that is both
internally issued and omitted is invisible to it, and the output says so. A
dump cannot be shown complete from the dump; the cross-check narrows the gap to
what never reaches a public log.

### A4. An operator who wants the tool to touch a target

The active modality is the only path that emits packets to a named host. The
attack is social rather than technical: talk the operator into adding a
third-party host to the allowlist and describing it as `reference`.

Control: the allowlist is committed, so the change is visible in history and in
review. The distinction between `self` and `reference` is documented in
`README.md` with the reasoning, and reference hosts are limited to
implementations that expect billions of connections.

Residual risk: a human decision, unenforceable in code. Recorded here so it is a
visible one.

### A5. Silent metric distortion

Not an adversary, but it belongs here because the consequence matches one. An
unrecognised key or signature OID resolving to `False` rather than `None`
reports a vulnerable certificate as quantum-safe. Nothing fails, no error is
logged, and the number moves in the flattering direction.

This shipped once, was found in review, and is fixed with the tri-state
convention documented in `ananke/collectors/certparse.py`. It is listed as a
security defect rather than a bug because the product of this pipeline is a
number somebody will budget against. Any new input path, including the
inventory import in T11, must be reviewed against this failure mode.

A second shape of the same consequence, recorded for this revision: the
generated report printed limitations the README had retracted, so the
deliverable claimed less visibility than the tool had. Fixed in 0.15.2 by one
shared list checked against the README registry.

### A6. A hostile estate that attacks the run itself

Distinct from A3: this adversary does not want a flattering number, they want
no number. One crafted file that crashes the collection stops the assessment.

Probed in the sprint 10 review: a 50 MB non-certificate file parses in under a
tenth of a second with an error recorded, and a path-traversal subject CN cannot
escape the store root because separators are flattened. One probe landed: a SAN
dNSName longer than the filesystem's 255-byte name limit crashed the write with
`OSError`, since a subject CN is capped at 64 bytes by X.509 but a SAN is not,
and host identity falls back to SAN. Store keys are now length-capped with a
digest suffix that preserves uniqueness.

Residual risk: resource exhaustion through volume rather than size. A directory
of millions of small valid certificates is processed one by one and bounded only
by the operator's patience. Accepted: the operator chose the directory.

### A7. Re-identification through quasi-identifiers

The HTML report embeds validity periods as date pairs for the horizon chart, on
the reasoning that dates carry no identity. Measured on the 34-host reference
estate, that reasoning fails: 100% of `(not_before, not_after)` pairs are
unique, and Certificate Transparency is a public index searchable by exactly
those fields. For any host present in CT, its date pair is a quasi-identifier,
and a reader of a third-party sector report could recover the "anonymous"
segments with one crt.sh query each.

Severity depends on the regime, which is why the control is a rule rather than
a fix. For a first-party estate the pairs are the commissioner's own hosts and
there is nobody to protect. For third-party modality A data the chart would be
a de-anonymisation oracle. Rule: **the horizon chart renders for first-party
aggregates only**; a modality A report gets counts and bands, never
per-certificate segments. Enforced in the renderer, pinned by a test, and any
future per-item visual for third-party data must answer this finding first.

The lesson reaches past the chart: suppressing names does not anonymise
records. Any per-item field precise enough to be plotted is precise enough to be
joined against a public index.

### A8. The delivery chain of the fixes themselves

Process, not code, and it failed twice in one week: patch sets transferred as
hand-assembled archives arrived incomplete (the 0.8.1 documentation patch never
landed; the 0.10.2 security patch landed without the file carrying the S3 fix),
and the gap was caught late both times, once by a failing test after
installation, once by inspecting the version string. A security fix that fails
to arrive without anyone noticing is worse than one not written, because the
changelog then claims a protection the tree does not have.

Control: every transfer carries a `MANIFEST.sha256`, and the verification step
after unpacking is `shasum -c`, not visual inspection. Since 0.14.2 the manifest
is derived from the tree rather than from a hand-picked file list, because a
manifest over a chosen set verifies that those files arrived and says nothing
about whether the set was sufficient. Transfers as `git format-patch` series add
a second check: `git am` refuses a patch that does not apply to the recorded
base. The green CI run on the pushed commit remains the final arbiter of what a
release contains.

## What this threat model does not cover

- The correctness of the detection content in `detection/`. Rules are validated
  for syntax and, where possible, against real telemetry; their evasion
  resistance is not modelled.
- Supply chain of the Python dependencies.
- The machine the tool runs on. If it is compromised, none of the above matters.
- Physical or network-level attacks against Certificate Transparency operators.
