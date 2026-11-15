# Contributing

## The gate

One command has to pass before anything is committed:

```bash
make verify
```

CI calls the same target rather than restating its steps, so green here means
green there. It runs the test suite with its coverage floor, ruff and mypy, the
Sigma and SPL structure checks, the scoring config validator, the limitations
registry, the repository map and the disclosure scan. The `verify` line in the
`Makefile` is the authoritative list.

Stage new documentation before running it. The prose scan derives the permitted
filenames from `git ls-files`, so the name of an untracked file is not yet
known to it.

## Non-negotiables

These are enforced by code, not by review, and the enforcement is the point.

- **No host-level data in commits.** `data/raw/` and `config/targets.yaml` are
  git-ignored. `tests/lint_disclosure.py` fails the build if a target list ever
  becomes tracked or if a host identifier reaches a committed aggregate.
- **No organisation named next to a finding.** Aggregation is by sector with a
  minimum bucket size. Certificate fingerprints count as host identifiers.
- **Provenance labels from the closed set.** `measured`, `reported`,
  `inference`, `assumption`, `speculation`, plus `estimate` and `not found` in
  planning documents (`README.md`, Provenance convention). A composite value
  inherits the weakest label. If you add a number, say where it came from.
- **No hardcoded model constants.** Weights, horizons and thresholds live in
  `ananke/scoring/weights.yaml` and `config/`.
  `test_no_hardcoded_weights_in_scoring_module` guards against drift back into
  code.
- **The active probe touches allowlisted hosts only.** Third-party estate is
  passive, public data only. The split is enforced in
  `ananke/active/handshake_demo.py` and in the directory layout; do not cross
  it.

## Prose

The repository's prose follows the same discipline as its code.

- No em-dashes anywhere in the tree. A hyphen with spaces or a comma does the
  job.
- Bracketed provenance labels come from the closed set above. Status markers
  (`[verify]`, `[todo]`, `[done]`, `[deferred]`, `[unknown]`) track work, not
  evidence.
- A cited source gets a link. The prose scan admits a reviewed list of citation
  hosts, `_PROSE_CITATIONS` in `ananke/collectors/disclosure.py`; adding one is
  a reviewed change, and an entry no document cites comes off the list.
- Command blocks are safe to paste into zsh: no inline `#` comments, globs
  quoted, no `<placeholder>` arguments, since `<` is a redirection there.
- A changelog entry names the defect, not the change, and every count in it
  comes from a command.

## A claim about the tool is a test, not a sentence

The "What this assessment will not tell you" section of the README is the part
a reviewer reads most carefully, and the easiest part of the repository to
falsify by accident: a limitation stops being true when a capability lands
three sprints later and nobody re-reads the sentence. It happened once. The
section claimed the assessment does not see cryptography at rest while a query
enumerating stored asymmetric keys had shipped sprints earlier, and three code
reviews missed it because the drift was between the code and what the
repository says about itself.

The rule that follows: **every bullet in that section is registered in
`tests/lint_limitations.py` with probes, and `make verify` runs the check.**
The check is bidirectional and fails closed: a new bullet with no registry
entry fails, and a registry entry whose bullet was removed fails, so a
limitation cannot be added, removed, or reworded without a decision about what
evidence would falsify it. A `must_exist` probe asserts the code property that
makes a claim true is still present; a `must_not_exist` probe asserts the
capability a claim denies has not appeared. A claim no pattern can prove
carries a `note` explaining why it is reviewed by hand. Since 0.15.2 the same
check covers the list the generated reports print.

The same treatment covers the repository map (`make lint-layout`) and the
assertion that CI calls the single gate. The principle behind all of it is
`ENGINEERING.md` section 0.

## Adding a detection rule

Structure must parse: `make lint-sigma` for Sigma, `make lint-spl` for the SPL
pack. Every rule carries a validation-status expectation in
`detection/README.md`. If you have not run it against a live sensor or tenant,
it is `[inference]`, and saying so is required.

## Optional pre-commit hook

```bash
cat > .git/hooks/pre-commit <<'HOOK'
#!/bin/sh
make verify || { echo "make verify failed; commit aborted"; exit 1; }
HOOK
chmod +x .git/hooks/pre-commit
```
