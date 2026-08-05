# Contributing

## The gate

One command has to pass before anything is committed:

```bash
make verify
```

That runs the unit tests, the Sigma structural validation, the scoring config
validator, and the disclosure lint. CI runs the same four. If `make verify` is
green locally it will be green in CI, and vice versa.

## Non-negotiables

These are enforced by code, not by review, and the enforcement is the point.

- **No host-level data in commits.** `data/raw/` and `config/targets.yaml` are
  git-ignored. `tests/lint_disclosure.py` fails the build if a target list ever
  becomes tracked or if a host identifier reaches a committed aggregate.
- **No organisation named next to a finding.** Aggregation is by sector with a
  minimum bucket size. Certificate fingerprints count as host identifiers.
- **Provenance labels are mandatory.** Measured, inference, assumption,
  speculation. A composite value inherits the weakest label. If you add a
  number, say where it came from.
- **No hardcoded model constants.** Weights, horizons and thresholds live in
  `scoring/weights.yaml` and `config/`. `test_no_hardcoded_weights_in_scoring_module`
  guards against drift back into code.
- **The active probe touches allowlisted hosts only.** Third-party estate is
  passive, public data only. This split is enforced in `active/handshake_demo.py`
  and in the directory layout; do not cross it.

## A claim about the tool is a test, not a sentence

The "What this assessment will not tell you" section of the README is load
bearing: it is the part a reviewer reads most carefully, and its honesty is the
project's whole pitch. It is also the easiest thing in the repository to
falsify by accident, because a limitation stops being true when a capability is
added three sprints later and nobody re-reads the sentence. This happened once:
the section claimed the assessment does not see cryptography at rest while a
query enumerating stored asymmetric keys had shipped sprints earlier. Three
code reviews missed it, because they reviewed code, and this was drift between
the code and what the repository says about itself.

The rule that follows: **every bullet in that section is registered in
`tests/lint_limitations.py` with probes, and `make verify` runs the check.**
The check is bidirectional and fails closed in both directions - a new bullet
with no registry entry fails, and a registry entry whose bullet was removed
fails - so a limitation cannot be added, removed, or reworded without a
conscious decision about what evidence would falsify it. A `must_exist` probe
asserts the code property that makes a claim true is still present; a
`must_not_exist` probe asserts the capability a claim denies has not quietly
appeared. A claim genuinely unprovable by pattern carries a `note` explaining
why it is reviewed by hand. Silence is not permitted: the failure mode this
guards against is precisely a true-sounding sentence nobody checked.

The same treatment now covers the repository map (`make lint-layout`) and the
assertion that CI calls the single gate, after all three went stale in the same
week and all three were caught by a reader rather than by a review.

The principle generalises past this one section. Where the repository makes a
claim about itself that a reader relies on - a scope boundary, a provenance
label, an enforced invariant - prefer to make it executable. A sentence drifts
silently; a test drifts loudly.

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
