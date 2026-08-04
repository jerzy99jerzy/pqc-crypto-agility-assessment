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

## Adding a detection rule

Structure must parse: `make lint-sigma`. Every rule carries a
validation-status expectation in `detection/README.md`. If you have not run it
against a live sensor or tenant, it is `[inference]`, and saying so is required.

## Optional pre-commit hook

```bash
cat > .git/hooks/pre-commit <<'HOOK'
#!/bin/sh
make verify || { echo "make verify failed; commit aborted"; exit 1; }
HOOK
chmod +x .git/hooks/pre-commit
```

**Stage new documentation before running `make verify`.** The disclosure
allowlist for repository filenames is derived from `git ls-files`, so an
untracked `.md` file is not yet a known filename and the prose lint will flag
it. This is deliberate: an untracked file must not be able to allowlist itself.
