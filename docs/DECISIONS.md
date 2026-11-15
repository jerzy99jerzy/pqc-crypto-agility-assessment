# Decisions

Rejected options and their reasoning, so the same debate is not had twice and a
reader can see what was considered rather than only what was built. Each entry
carries the condition that should reopen it: a decision without one stops being
a judgement made under known constraints and becomes a rule nobody remembers the
reason for.

---

## Mass active scanning of third-party estate

Date: 2026-07-28. Status: rejected

**Decision.** No nmap-style sweep, no mass active probing of any estate the
operator does not control.

**Reasoning.** The legal and optical downside followed from the goal, not the
technique. A single handshake is defensible; a sweep carries reconnaissance
connotations, and "I ran nmap against 500 banks" and "I performed a standard TLS
handshake" describe similar traffic with opposite optics. NIS2-scope and
financial entities log and monitor, so the risk of a SOC alert attached to an IP
with the author's name on the repository is asymmetric. The marginal signal was
low in any case: PQC adoption is early enough that the finding reads "almost
nobody supports hybrid", which is establishable from a sample.

**What would change this.** An engagement where the target authorises active
testing in writing. That is a different modality with a different ethical basis,
not a relaxation of this one.

---

## An nmap NSE plugin for hybrid group detection

Date: 2026-07-28. Status: rejected

**Decision.** Do not write one.

**Reasoning.** `ssl-enum-ciphers` does not probe hybrid supported_groups out of
the box; fixing that means parsing key_share, codepoints and HelloRetryRequest.
It duplicates what OpenSSL 3.5 does in one line, and public PQC scanners already
exist. The effort moves to where there is no return and hides the actual
differentiator, which is scoring, provenance and detection content.

**What would change this.** Nothing foreseeable. The capability exists elsewhere.

The pattern is worth naming beyond this instance: reaching for the elaborate,
cognitively attractive option instead of the repeatable work that closes the
gap.

---

## Dual licensing rather than permissive

Date: 2026-08-04. Status: adopted, superseding MIT

**Decision.** AGPL-3.0-only, or a commercial licence from the author.

**Reasoning.** The plausible commercial deployment of this work is a network
service, so AGPL section 13 is the operative clause. The structure exists so
that detection content cannot enter a consultancy's delivery model without a
commercial conversation. Tags v0.5.0 through v0.7.0 shipped under MIT and that
grant is not retroactively revocable; relicensing binds later releases only.

**What would change this.** A distribution partner who cannot accept copyleft
for reasons that survive scrutiny, or a decision to treat the repository as a
portfolio artefact only. Both are commercial calls, not engineering ones.

---

## The report generator produces measurable sections only

Date: 2026-08-05. Status: adopted

**Decision.** Owners, deadlines and recommended sequencing are written by hand
per engagement rather than generated.

**Reasoning.** Automatically assigning an owner inside an organisation the tool
has never seen is exactly the kind of confidence the rest of the project avoids.
The generator can say what is true of the data; it cannot say who fixes it.

**What would change this.** A template mechanism where the operator supplies
their own role mapping as configuration. That is generation from operator input,
which is a different claim, and would carry `reported` provenance.

---

## The limitations section is fixed, not generated, and states the method's scope

Date: 2026-08-05, amended 2026-11-15. Status: adopted

**Decision.** The "what this will not tell you" section is written, registered
in `tests/lint_limitations.py`, and does not shrink based on what a particular
run happened to include. It states the scope of the method as technical facts
about what passive observation can and cannot see; commentary about the section
itself stays out of it. The generated report prints the same list (0.15.2).

**Reasoning.** A generated version would disappear when an engagement became
most complete, which is when a reader most needs to know what the number does
not cover. `[inference]` These limits describe what public data can show about
an estate; publishing them gives nobody a way to evade the measurement or the
guard.

**What would change this.** A change in what the method can observe, in which
case the section changes with the code and the registry makes the change
explicit. Or a limitation whose publication would help someone evade the
measurement or the guard: that one would be kept out of the published section.

---

## A batch orchestrator for the active probe

Date: 2026-07-28. Status: deferred

**Decision.** The active probe runs as a plain loop over the allowlist.

**Reasoning.** Rate limiting, resumability, atomic writes and an idempotent
per-host store are the right pattern at scale, and the passive collector has
them because its target count justifies them. For a dozen allowlisted hosts an
orchestrator adds machinery nothing needs.

**What would change this.** An allowlist large enough that an interrupted run
costs real time to repeat, which would mean a first-party engagement with many
declared `self` hosts.

---

## Citation hosts are admitted in the prose scan only

Date: 2026-11-15. Status: adopted

**Decision.** A short, reviewed list of standards bodies and publishers may
appear as hostnames in committed prose, by exact name, so documents can link
their sources. The structural guard does not consult the list.

**Reasoning.** Until 0.15.3 the prose scan rejected every hostname, so no
document linked a source, and claims about RFCs, papers and vendor features
asked to be taken on trust. Admitting the hosts in prose only keeps the strict
path, the one collected data travels, unchanged; a test pins that each citation
host still fails there. An entry no document cites comes off the list, so the
list cannot grow into coverage nobody uses.

**What would change this.** A citation host that is also an assessed estate,
which would make naming it in prose ambiguous. At that point the host comes off
the list and the citation moves into a code span.

---

## No web UI or hosted service

Date: 2026-08-05. Status: rejected for now

**Decision.** The tool stays a local command-line pipeline producing files.

**Reasoning.** A hosted service inverts the data model: raw host-level records
would have to leave the operator's machine, which is the one thing the current
architecture guarantees never happens. It also changes the licence question, the
threat model and the support burden simultaneously. Recorded because it is
obvious now and will not be in three months, when nobody can reconstruct whether
it was ever weighed.

**What would change this.** A buyer for whom self-hosting is the blocker, plus a
design where raw records stay on their side and only aggregates cross the
boundary. The second condition is not optional.
