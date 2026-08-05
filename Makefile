.PHONY: help install select collect aggregate score capability report validate verify coverage handshake test lint-sigma lint-disclosure

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

install:         ## editable install with dev extras (pytest, pytest-cov, pysigma)
	pip install -e ".[dev]"

select:          ## build config/targets.yaml from a pinned public ranking (RANKING=path)
	pqc-select --ranking $(RANKING) --suffix $(or $(SUFFIX),.pl) --top $(or $(TOP),10000)

collect:         ## passive CT collection (third-party estate, public data only)
	pqc-collect --targets config/targets.yaml -v

aggregate:       ## rebuild sector aggregates from the local raw store
	pqc-collect --aggregate-only

score:           ## HNDL scoring, sector level
	pqc-score --from-store

capability:      ## resolve PQC capability from a software inventory export (INVENTORY=path)
	pqc-capability --inventory $(INVENTORY)

report:          ## render docs/report.md from committed aggregates
	pqc-report

handshake:       ## active probe, allowlisted hosts only, requires OpenSSL >= 3.5
	pqc-handshake --allowlist config/reference_hosts.yaml

test:            ## unit tests, no network
	python -m pytest

coverage:        ## unit tests with coverage, enforces the floor in pyproject.toml
	python -m pytest --cov

lint:            ## style and types; SKIPs only when the tool is absent
# `A && B || C` reports success when B fails, because the shell runs C and
# returns its status. That made this target incapable of failing: a real ruff
# error printed "SKIP" and the gate went green. Absence read as success, in the
# target that exists to prevent it. if/then/else propagates the exit code.
	@if command -v ruff >/dev/null 2>&1; then ruff check .; \
	else echo "SKIP ruff (pip install -e '.[dev]')"; fi
	@if command -v mypy >/dev/null 2>&1; then mypy ananke; \
	else echo "SKIP mypy (pip install -e '.[dev]')"; fi

lint-sigma:      ## structural validation of the Sigma pack (needs pysigma)
	python tests/validate_sigma.py

lint-spl:        ## structural discipline checks over the SPL pack
	python tests/validate_spl.py

lint-limitations: ## check the limitations section against the tree
	python tests/lint_limitations.py

lint-layout:     ## the README repository map, checked against the tree
	python tests/lint_layout.py

lint-disclosure: ## scan committed artefacts for host identifiers
	python tests/lint_disclosure.py

validate:        ## scoring config: saturation, floors, weights, bands
	pqc-score --validate-config

verify: coverage lint lint-sigma lint-spl validate lint-limitations lint-layout lint-disclosure  ## everything CI runs
