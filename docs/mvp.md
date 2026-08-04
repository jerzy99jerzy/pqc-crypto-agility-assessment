# Release criteria

Project codename: ANANKE.

Version 1.0, 2026-08-04.

`TODO.md` states what is not done. This file states what *finished* means, which
is a different question and was unanswered for eight sprints. Without it every
sprint can be justified as the next one: a codebase always yields another
defect, and reviewing your own tree is more comfortable than acquiring the
access that actually blocks progress.

Three audiences are plausible for this artefact and they are not the same
product. Each has its own definition of done, its own distance, and its own
blockers. **Pick one before starting the next sprint.** Two of the three are
blocked on things no amount of engineering will produce.

Provenance labels follow the repository convention: `[measured]` observed,
`[inference]` judgement, `[speculation]` explicitly uncertain.

---

## MVP-A: portfolio artefact

**Audience.** A technical reader assessing method and discipline: a hiring
panel, a conference committee, a peer reviewing the approach.

**What it has to prove.** That the author can build a measurement instrument and
be honest about its limits. The headline number is irrelevant to this audience;
the provenance layer, the disclosure guard and the "will not tell you" section
are the product.

**Definition of done.**

- [x] Passive collection pipeline with an idempotent store and atomic writes.
- [x] Scope statement enforced in executable code, not prose, with regression
      tests for each defect found in it.
- [x] Provenance labels applied to every load-bearing claim, including the
      capability thresholds.
- [x] Detection content published with an honest validation-status table.
- [x] Packaging, CI, coverage floor, changelog, license.
- [ ] Every claim in `README.md` backed by something in the tree. **One claim is
      currently not**: PQC readiness is described as demonstrated against own
      infrastructure, and no `self` host exists (T2).

**Distance.** `[inference]` Zero sprints of code. One decision: either declare a
`self` host, or narrow the claim to reference implementations only. An hour
either way.

**Explicitly out of scope.** Live data. A published figure. Anything requiring a
tenant, credentials or a customer.

---

## MVP-B: paid discovery engagement

**Audience.** A NIS2 or DORA-scope organisation buying an inventory assessment
against the 2026 identification milestone.

**What it has to prove.** That the pipeline produces a defensible number about a
real estate, and that the method survives someone else's scrutiny of how the
number was reached.

**Definition of done.**

- [ ] Sector classification driven by an authoritative register rather than the
      `contains:` keyword heuristics currently in `config/classification.yaml`,
      with the collision counter reporting zero cross-sector collisions on the
      real target set (T7).
- [ ] One complete end-to-end run over a real target set, from ranking through
      selection manifest to sector aggregates, with the raw store retained
      locally and only aggregates committed.
- [ ] `docs/report.md` generated from that run and readable by a non-technical
      risk owner without a walkthrough.
- [ ] The active modality demonstrated against at least one host under the
      operator's control (T2, shared with MVP-A).
- [ ] A stated position on what the engagement does *not* deliver, in the
      contract rather than only in the repository.

**Distance.** `[estimate]` Two to three sprints of repository work. The gating
item is not code: it is register data for T7, which is free to obtain and
tedious to normalise.

**The real gap.** Nothing in the repository produces a client-facing deliverable
beyond `docs/report.md`, and that has never been generated from real input. This
is the only item on the list that cannot be unblocked with money or access.

---

## MVP-C: subscribable detection content

**Audience.** A security operations team with a detection budget and no
PQC-native content to deploy.

**What it has to prove.** That the rules run in the buyer's stack, unmodified,
and return sensible results on real telemetry. Content nobody has executed once
is not a product.

**Definition of done.**

- [ ] Every KQL query validated against a live tenant with `getschema` or a
      sample event, and its row in `detection/README.md` moved from
      `[inference]` to `[measured]` (T4).
- [ ] Zeek codepoint spelling for `0x11EC` confirmed on a real sensor build, and
      the unused branch pruned from the rule (T5).
- [ ] Each Sigma rule compiled to at least one concrete backend via `sigma
      convert`, with the output committed. Rules that only parse are not
      deployable content.
- [ ] Versioning and a maintenance commitment stated, since a ruleset that is
      not maintained is a one-off download, not a subscription.

**Distance.** `[inference]` Not expressible in sprints. T4 and T5 are access
problems, and the compile step is unstarted work that is not in `TODO.md` at
all.

**Commercial note.** `[inference]` This is the highest-margin path in the
expansion analysis and the furthest from ready. That gap is the decision the
project has been deferring.

---

## Blocker cost table

`[measured]` where a price is cited from a vendor page, `[estimate]` otherwise.
Prices verified 2026-08-04 and will drift.

| Blocker | Cost of entry | Nature |
|---|---|---|
| T1 OpenSSL 3.5 client | none | lab work; available via package manager or container image |
| T5 Zeek sensor build | none | lab work; official container image, accepts a pcap from T1 |
| T2 operator-owned host | domain registration, plus optionally a small VPS | purchase, trivial |
| T3 Censys enrichment | credit package, minimum around USD 100; the free tier exposes lookup endpoints only, not search | purchase |
| T4 Microsoft tenant | none inside a 30-day E5 trial; the free developer sandbox now requires a paid Visual Studio standard subscription | time-boxed access |

T1 and T5 are paired: a handshake captured from the operator's own client feeds
the sensor, which resolves the codepoint question and turns one detection rule
from inference into measurement. That pairing is the cheapest real progress
available and requires nobody's permission.

---

## Integrations not tracked in `TODO.md`

`[inference]` Four gaps that no existing item covers:

1. **Sigma backend compilation.** The rules parse; there is no evidence they
   convert to a deployable query for any specific SIEM. Gating for MVP-C.
2. **Ranking snapshot identity.** Reproducibility needs the Tranco list
   identifier recorded, not a filename.
3. **Certificate Transparency redundancy.** `crt.sh` is a single free community
   service and the only inlet of the passive layer. Acceptable for MVP-A,
   a single point of failure for MVP-B.
4. **Client deliverable format.** See MVP-B above.

---

## How to use this file

Amend it when a criterion is met, in the same commit that meets it. A criterion
that moves because it turned out to be inconvenient should be recorded as a
scope change with its reason, not quietly edited: the project's whole claim is
that it does not adjust the measurement to flatter the result.
