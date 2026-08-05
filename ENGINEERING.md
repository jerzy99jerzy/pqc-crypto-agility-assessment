# ENGINEERING.md

**Portable engineering standard. Copy into any repository in this portfolio.**

Version 1.0, 2026-08-05. Distilled from `pqc-crypto-agility-assessment`
(ANANKE), `cve-digest`, `phantomatics`, `signal-journal-bot` and `gmach`, and
from what went wrong in each.

Nothing here is aspiration. Every rule exists because its absence produced a
specific defect that shipped, and the defect is named so the rule can be argued
with rather than obeyed.

---

**These are single-maintainer repositories.** That is why the gate lives in
`make verify` rather than in a review process, and why there is no issue or
pull-request ceremony below. It is a deliberate fit to the situation, not an
omission. Where a rule substitutes for a second pair of eyes, it says so.

---

# Part I. What a repository looks like

## 0. The one principle

**A claim the repository makes about itself should be executable.** A sentence
drifts silently; a test drifts loudly.

This is the newest rule and the one that generalises furthest. It was learned
the expensive way: ANANKE's README claimed the tool could not see cryptography
at rest while shipping a query that enumerated stored asymmetric keys. Three
code reviews missed it, because all three reviewed code and the divergence was
between the code and the prose describing the code. It was found by a question.

Everything below is an application of this principle to a different surface.

---

## 1. Repository skeleton

Create in this order. The order matters: it is descending order of how
expensive the thing becomes to add later.

```
<repo>/
├── README.md              # thesis, scope, what it will NOT tell you, layout
├── ENGINEERING.md         # this file
├── CONTRIBUTING.md        # invariants a contributor must not break
├── SECURITY.md            # how to report a defect in the guarantees
├── LICENSE / NOTICE       # decided at creation, not at v0.7
├── CHANGELOG.md           # every release, including the ones folded into others
├── TODO.md                # open items, each with a status and acceptance test
├── Makefile               # `verify` is the only gate anyone needs to know
├── pyproject.toml         # single source of dependency truth
├── <package>/             # ONE namespace, never five top-level directories
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   ├── test_<domain>.py   # behaviour by area
│   ├── test_sprint<N>.py  # regression, one file per sprint
│   └── lint_*.py          # executable claims about the repo itself
├── docs/
│   ├── ARCHITECTURE.md    # what talks to what, with a block index
│   ├── MECHANISMS.md      # how each mechanism works
│   ├── METHODOLOGY.md     # what may be claimed, plus the defect log
│   ├── THREAT-MODEL.md    # adversaries against this tool
│   ├── MVP.md             # release criteria per audience
│   └── report.md          # generated output stays lowercase
└── .github/workflows/ci.yml
```

**Naming convention, and the reason.** Design documents are `UPPERCASE.md`,
generated artefacts are `lowercase.md`. The case is not decoration: it tells a
reader at a glance whether a file is authored or produced, and therefore
whether editing it is meaningful. `report.md` is regenerated on every run;
editing it is a mistake the filename should discourage.

**One namespace package.** Five top-level directories named `collectors`,
`scoring`, `inventory`, `reporting`, `active` planted five collision candidates
in `site-packages` on every install. Slug stays descriptive (a search term),
console scripts stay grouped by prefix (typed by hand), the import path is a
namespace and must be unique rather than descriptive. Fixing this at v0.10 cost
a breaking change and surfaced two latent path bugs; at v0.1 it costs nothing.

**Data policy, decided at creation.** Three tiers, and the boundary is enforced
by code rather than by care:

| Tier | Lives | Committed |
| --- | --- | --- |
| Raw, per-subject records | `data/raw/`, git-ignored | never |
| Aggregates, counts only | `data/aggregates/` | yes |
| Generated documents | `docs/report.*` | yes, regenerable |

The rule that makes it hold: **the path from raw to committed runs through
counting and then through a guard, and there is no other path.** In ANANKE that
is `assert_no_host_identifiers`; in a repository handling personal data it is
whatever the equivalent identifier is. Write the `.gitignore` for these three
tiers in the first commit, because retrofitting it means rewriting history.

Secrets: never in the tree, never in a fixture, never in a test. A fixture that
needs a credential generates one at runtime. Every repository in this portfolio
that touches an API should assume its raw store is the most sensitive thing on
the disk and treat it accordingly.

**Codenames.** Documentation and conversation get a codename (this portfolio
uses Lem: ANANKE, phantomatics). The slug stays machine-boring. Whether the
codename becomes the package name is a per-repo decision, but it must be stated
in the README rather than left implicit, because that is where the inconsistency
lives otherwise.

---

## 2. The single gate

`make verify` runs everything, and **CI calls `make verify` rather than
restating its steps.**

A workflow that lists checks individually drifts the moment a check is added to
the Makefile. In ANANKE this shipped: `lint-spl` and `lint-limitations` were
added to `verify` and were local-only for a day, while the Makefile comment
said "everything CI runs". The rule is a consequence: if it is not in `verify`,
it does not run anywhere.

Minimum contents of `verify`:

| Target | Fails the build when |
| --- | --- |
| `coverage` | unit tests fail, or coverage drops below the floor |
| `lint` | style or types regress (`ruff check`, `mypy <package>`) |
| `lint-limitations` | a claim in the README no longer matches the tree |
| domain lints | the repository's own invariants are violated |

**Coverage is a floor, not a target.** Set it in `pyproject.toml`, at roughly
the current level minus a few points, and raise it when a sprint genuinely
raises coverage. A target invites tests written for the number; a floor only
prevents regression.

**An empty test suite must fail the gate, not pass it.** A fresh `make verify`
on a repo with no tests exits green by default, because pytest treats "nothing
collected" as success. That is the same failure class as unknown-resolves-safe:
absence read as success. Configure pytest so zero collected tests is a failure
(it exits 5 on no tests; do not swallow that), and set the coverage floor above
zero from the first commit. A gate that passes an empty repo is not a gate, and
this shipped in the first draft of this very document's starter kit.

**Type checking and style are not optional.** `cve-digest` runs `ruff` and
`mypy` in CI; ANANKE does not, and the gap is unjustified. Converge upward.

**Test on the version you develop on.** ANANKE's CI pinned 3.12 while local
work happened on 3.14. Use a matrix with both ends of the supported range.

### Dependencies and cost

**Every new runtime dependency is justified in the changelog entry that adds
it.** ANANKE runs on two (`cryptography`, `PyYAML`) and that is a decision, not
an accident: a tool whose pitch is auditability is weakened by a dependency tree
nobody can audit. Development dependencies are cheaper and still not free.

**A correct artefact nobody can afford is not a deliverable.** This was written
about detection queries, where a search that returns the right answer and costs
a fortune to schedule is not deployable content, but it generalises: a pipeline
run that takes six hours, a report that is forty megabytes, a check that adds
two minutes to every commit. Cost is a property of the deliverable, and it
should be measured before the thing is called done rather than discovered by the
person paying for it.

### Hygiene jobs (no interpreter needed)

Cheap, and each one exists because it went wrong:

- **No tracked `*.patch` / `*.diff`.** Transfer artefacts committed by
  reflex; `cve-digest` still carries two in its root.
- **No absolute developer paths** (`/Users/...`, `/home/...`) in tracked source.
- **Tag matches declared version.** A tag whose artefacts were built from a
  different version string happened twice in one day.

---

## 3. Test density and shape

**One regression test file per sprint, named for the sprint.** `test_sprint9.py`
is not a category, it is a date stamp: it tells a reader which release the cases
in it were written against, and its docstring explains the defect class. Domain
files (`test_pipeline.py`, `test_collection.py`) hold behaviour; sprint files
hold "this specific thing was broken and must not return".

**A regression test must be verified to fail against the previous release, not
assumed to.** Unpack the last tag into a scratch directory, drop the new test
file in, run it, confirm red. A regression test that passes against the buggy
version documents nothing and is worse than none, because it implies coverage
that does not exist. This is fifteen minutes per sprint and it has caught
mis-scoped tests more than once.

**Density guidance, from what actually held up:**

| Code | Expectation |
| --- | --- |
| Enforcement of a stated guarantee (guards, scope, provenance) | every branch, both directions, plus an adversarial case |
| Parsers over untrusted input | malformed, truncated, hostile, oversized; must never raise |
| Classification with a tri-state | one test per state, and one asserting unknown is not the safe state |
| Orchestration and CLI wiring | smoke level; argparse wrappers exercised through their callees |
| Generated output | that it contains what it claims and nothing it promised to exclude |

Roughly 75-80% line coverage is what this shape produces naturally. Chasing 95%
means testing argparse.

**A tool that enforces a practice is tested against a fresh repo, not the one
it grew in.** The starter kit for this document passed every check inside the
mature repository it was extracted from and failed four ways on an empty one:
`make verify` went green with no tests, a lint crashed instead of guiding, and
the "generic" CI still named a sibling repo's targets. Found by running it on a
bare directory, which is the only place its assumptions are visible. Any
portable artefact is probed in the environment it claims to support before it
is shipped, exactly as any parser is probed on hostile input.

**Adversarial fixtures earn more than clean ones.** `phantomatics` validated its
channel weights against an adversarial world and the clean world only ever
confirmed the obvious; ANANKE's `pqc-fixture` has `clean`, `partial` and
`hostile` for the same reason. Ship a fixture generator as a CLI command, not a
test helper: it also means someone can run the repository with no data of their
own.

---

## 4. Provenance and the tri-state

**Four labels on every load-bearing claim**, in code, in output records and in
generated documents:

| Label | Means |
| --- | --- |
| `measured` | read from an artefact without interpretation |
| `reported` | supplied by an interested party; each field parsed by us, the completeness is their claim |
| `inference` | derived from observable proxies |
| `speculation` | explicitly uncertain, carried rather than resolved |

`reported` is the one most repositories omit and the one that matters
commercially: it is the difference between "we measured your estate" and "we
measured what you handed us". A composite inherits the weakest label of its
inputs.

**Unknown is never the safe state.** An unrecognised algorithm, an unresolvable
version, an absent threshold: all resolve to `None` and are reported as
unknown. Returning `False` inflates the flattering number silently, which is
the single worst failure mode for any tool whose product is a measurement. This
shipped once in ANANKE (F1) and is now checked on every new input path, because
it recurs by default: `False` is what a naive implementation returns.

**Version comparison uses a zero-padded numeric key, never string comparison.**
`"3.5"` sorts below `"3.10"`. This also shipped once (F2).

---

## 5. MVP separate from sprints

These answer different questions and conflating them is why projects run
indefinitely.

**`TODO.md` says what is not done.** Every item carries a status
(`ready` / `blocked-external` / `decision` / `debt`), the blocker where one
exists, and **an acceptance test**, so "done" is not a matter of opinion.

**`docs/MVP.md` says what finished means, per audience.** ANANKE went eight
sprints without this and the cost was invisible until it was named: a codebase
always yields another defect, so without exit criteria every sprint can be
justified as the next one, indefinitely.

Define one MVP per plausible buyer, each with its own definition of done, its
own distance estimate, and its own blockers. Then note which blockers are
engineering and which are access, purchase or decision, because **the second
kind does not shrink by writing code** and that distinction is the one most
often blurred. In ANANKE, three consecutive sprints were reviews of the
project's own code while five external blockers sat untouched; naming it
changed the next decision.

**Amend release criteria in the same commit that meets them.** A criterion that
moves because it turned out to be inconvenient is a scope change and gets
recorded as one, with its reason. Quietly editing it is how a project starts
adjusting the measurement to flatter the result.

---

## 6. Sprint discipline

A sprint has a defect class or a capability, not a list of chores.

1. **Establish the baseline.** `make verify` green before touching anything. If
   it is not green, that is the sprint.
2. **Probe rather than read.** Every review in this portfolio that found
   something real found it by running a probe against the code, not by reading
   it. The three ANANKE guard defects, the k-anonymity failure in the chart, the
   IPv6 gap: all empirical, all invisible to careful reading.
3. **Fix, then generalise.** Fix the instance, then ask what class it belongs
   to and close the class. The dead allowlist entry became a test that fails on
   any unreachable entry; the stale README claim became `lint_limitations.py`.
4. **Write the regression test and verify it fails against the last tag.**
5. **Review your own diff before packaging.** In this portfolio, self-review
   after the work catches roughly one real defect per sprint: the site-packages
   sentinel, the misleading `granularity` field, the issuer counter that would
   have leaked host identity.
6. **Record the defect in `docs/METHODOLOGY.md`**, with what it was, why it
   survived, and what class it belongs to. The defect log is the most
   persuasive document in the repository for a technical reader, because
   nobody fakes those.
7. **One release per sprint**: version bump, changelog entry, tag, artefacts
   built from the tag.

**Changelog entries state the defect, not the change.** "Fixed underscore
handling" is worthless. "Host identity adjacent to an underscore passed both
guards; `\b` never fires between `_` and a letter; present since sprint 2" tells
a reader what to check in their own code.

---

## 7. Release and transfer

**Never move a published tag.** A tag describing code that has not changed is
correct even when the surrounding metadata is not. Cut a patch release instead
and say in the changelog what happened. This came up twice; both times the
patch was cheaper and more honest than the rewrite.

**Build artefacts from the tag, not from `HEAD`.** `rm -rf dist build
*.egg-info` before `python -m build`, and check `ls dist` shows only the
expected version before publishing. Stale artefacts from the previous version
got as far as an upload attempt once.

**Every hand-assembled patch set carries a `MANIFEST.sha256`**, and the
verification step after unpacking is `shasum -c`, not visual inspection. Two
patch sets in one day arrived incomplete before this rule existed, one of them
carrying a security fix whose changelog entry then claimed a protection the
tree did not have. A security fix that silently fails to arrive is worse than
one never written.

**Renames keep the old reader for a defined window.** When a field, key or
flag is renamed, every read site accepts both for at least two minor releases,
the new name is written, and the changelog states when the old one stops being
read. A store or a config written by an older version must keep working, and
the cost of the compatibility branch is trivial next to a client whose data
silently reclassifies.

**Onboarding is tested, not assumed.** Clone into a fresh directory and follow
the README from zero, noting where you stop. This is the same probe that found
four defects in this document's own starter kit, and it is the only check on
the assumption that a repository is usable by someone without the author's
memory of it. Run it whenever a repository might be handed to somebody, and
before it is shown to anyone whose opinion matters. A repository that only its
author can run is a repository with a bus factor of one, which is fine as a
personal tool and disqualifying as a commercial artefact.

**A changelog entry without a tag is a debt.** If a release is folded into a
later one, say so in the entry rather than leaving a reader to search for a tag
that does not exist.

---

## 8. Documentation that earns its keep

**`README.md` must contain a "What this will not tell you" section**, and it is
the part a competent reader reads first. Write it in layers rather than as flat
denials: "does not see cryptography at rest" is simultaneously false and
unhelpful when the honest answer is that the layer is four things and two of
them are out of scope entirely. Then register every bullet in
`tests/lint_limitations.py` so it cannot go stale.

**`docs/THREAT-MODEL.md` models adversaries against the tool**, not against the
world. Include: who benefits from the output being wrong, what an interested
party supplying input can do, what a hostile input can do to the run itself,
and what the delivery chain of the fixes can do. Re-probe the residual risks on
review rather than re-reading them; ANANKE's threat model overstated two of its
own holes and missed a real one until the claims were tested.

**`docs/ARCHITECTURE.md` keeps a block index**: a table mapping each block in
the diagram to the document section explaining it. Maintained as a table
precisely so a rename leaves a visibly stale row.

**Mermaid diagrams: no semicolons inside statements.** `;` is a statement
separator, and a diagram that fails to parse is invisible to every local check
because the markdown is valid and only the forge renders it. Add a lint.

---

# Part II. How the work runs

Part I describes what a repository should look like. This part describes how to
decide what to do next, which is where the expensive mistakes actually happen.
None of these rules is about code.

---

## 9. Session discipline and choosing work

**Before a sprint, one question: does this bring the project closer to a
recipient, or does it improve something already built?**

Both are legitimate. The failure is not noticing the ratio. In ANANKE, sprints
6, 7 and 8 were consecutive reviews of the project's own code while five
external blockers sat untouched. Each was justified on its own terms and each
found a real defect. The pattern was still avoidance, because reviewing your own
tree is cognitively pleasant and buying a domain, standing up a tenant or
writing to a contact is not.

**Work that requires waiting on someone else takes precedence over work in the
editor**, because only the first kind has a window. A code item is available at
midnight in six weeks; a conversation with a prospect is not, and a trial
licence expires.

**Distinguish the two blocker types explicitly in the backlog.** An engineering
blocker shrinks when you write code. An access, purchase or decision blocker
does not shrink at all, no matter how many sprints pass. Counting sprints
toward a goal gated by the second kind is a category error, and it is the most
common way a solo project stalls while feeling productive.

**Releases per session are a signal, not an achievement.** Eight in one day
means the work was available and the discipline held, or it means the editor was
the comfortable place to be. Both look identical from inside. If a session
produces several releases and no external step, name that at the end rather than
counting it as a good day.

**Stop at a coherent state, not at exhaustion.** A repository at a tag with a
green pipeline and an honest changelog can be left for a week. One with a
half-applied patch cannot, and the next session starts by reconstructing state
instead of doing work.

---

## 10. Working with an AI assistant on a repository

This is how these repositories are actually built, so it belongs in the
standard rather than in habit. Every rule below comes from a specific failure in
one session.

**Verify claims about the tree; do not accept them.** An assistant will state
that a module exists, that a fix shipped, or that a test covers a case, with the
same confidence whether or not it checked. In this portfolio that produced a
false statement about a source adapter that had never been written, which then
travelled into an email to a prospect. The rule is mechanical: any claim about
the current state of the code is `grep`-verified before it is repeated
anywhere outside the session.

**Keep state in files, not in the thread.** A long session accumulates
assumptions about what is applied where. Two patch sets in one day arrived
incomplete because the assistant packaged files based on a remembered state of
the tree rather than a checked one. The counter-rule is in Part I: every
transfer carries `MANIFEST.sha256` and is verified with `shasum -c` before
commit, not after.

**Understand the transfer boundary.** The assistant runs in a container with no
access to your disk. Running a command in your terminal is not a channel to it;
a file must be attached, and generating an archive locally is not the same as
delivering it. Several exchanges in one session were spent on this alone.

**Demand probes, not readings.** Every review in this portfolio that found
something real found it by running something. The three disclosure-guard
defects, the unique-date re-identification vector, the CI that had drifted
weaker than the Makefile: all empirical, all invisible to careful reading of the
same code. "I reviewed it and it looks correct" is not a review.

**Ask for the correction, not the reassurance.** The useful output is
"your claim X is contradicted by Y", and an assistant will produce it if the
standing instruction is to correct rather than agree. This one is a preference
setting, not a rule of the repository, but it changes what the collaboration is
worth.

---

## 11. Decisions and their conditions for revisit

**`docs/DECISIONS.md` is mandatory, and it records what was rejected.**

ANANKE's project brief has a section on rejected options - a mass active scan,
an nmap NSE plugin - with the reasoning preserved. It is one of the more
valuable documents in that repository for two reasons. It stops the same option
being relitigated every few weeks, and it demonstrates operational judgement to
a technical reader more convincingly than any list of what was built.

One entry per decision:

```markdown
## <what was decided>
Date: <when>. Status: rejected | adopted | superseded by <entry>

**Decision.** <one sentence>

**Reasoning.** <why, in terms that will still make sense out of context>

**What would change this.** <the observation, price, or event that should
reopen it>
```

The last field is the one usually omitted and the one that matters. A decision
without a revisit condition becomes dogma: it stops being a judgement made under
known constraints and becomes a rule nobody remembers the reason for. Writing
"revisit if a client supplies a real export" or "revisit if the price drops
below X" keeps it a decision.

Record the ones that felt obvious too. "We are not building a web UI" is obvious
until three months later, when it is not, and nobody can reconstruct whether it
was considered.

---

## 12. Convergence across the portfolio

Divergences currently costing more than they buy:

| Divergence | Recommendation |
| --- | --- |
| Three licences (MIT, Apache-2.0, AGPL+commercial) | Each may be right; write one paragraph per repo saying why. An unexplained spread is the first thing a partner asks about |
| Version schemes (`0.7.6.1` vs `0.13.1`) | Pick semver and hold it |
| Docs case (`MECHANISMS.md` vs `mechanisms.md`) | Uppercase for design documents, portfolio-wide |
| `ruff`/`mypy` in `cve-digest` only | Everywhere |
| Python matrix in `cve-digest` only | Everywhere, and include the version you develop on |
| Hygiene job in `cve-digest` only | Everywhere, it costs four seconds |
| `docs/MVP.md` in ANANKE only | Everywhere; it is the cheapest document with the largest effect on how a project ends |
| Releases in ANANKE only | `cve-digest` has a changelog and no tags |
| `requirements.txt` beside `pyproject.toml` | Keep one source of truth, or state in the file which one it mirrors |

**The optimisation worth making next:** stop hand-assembling this. The skeleton,
the Makefile, the CI workflow, `lint_limitations.py` and the document stubs are
mechanical. A `repo-template` repository used as a GitHub template, or a small
`cookiecutter`, turns "remember to add the hygiene job" into a property of every
new repository. Given six repos and a demonstrated pattern of the same three
things being forgotten, this pays back on the next one.

**The second optimisation:** a portfolio-level check, run occasionally rather
than in CI, that clones each repository and reports which of the rules above
each one fails. Not to enforce uniformity for its own sake, but because the
drift found today (CI weaker than the Makefile, patch files in a public root,
a changelog with no tags) was all invisible from inside the individual repos.

---

## 13. The short version

Eleven rules, if the rest is too long to re-read:

1. A claim about the tool is a test, not a sentence.
2. `make verify` is the only gate; CI calls it rather than restating it.
3. Unknown is never the safe state.
4. A regression test is verified to fail against the previous release.
5. Coverage is a floor, not a target.
6. `TODO.md` says what is not done; `docs/MVP.md` says what finished means.
7. Access blockers do not shrink by writing code; name which is which, and prefer the work that has a window.
8. Verify what an assistant claims about the tree; never repeat it unchecked.
9. Never move a published tag; every transfer carries a manifest, verified before commit.
10. Record what you rejected, and the condition that would reopen it.
11. Probe, do not read - including the tools that enforce these rules, in the environment they claim to support.
