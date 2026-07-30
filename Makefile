.PHONY: help select collect aggregate score capability report validate verify handshake test lint-sigma lint-disclosure

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

select:          ## build config/targets.yaml from a pinned public ranking (RANKING=path)
	python collectors/select_targets.py --ranking $(RANKING) --suffix $(or $(SUFFIX),.pl) --top $(or $(TOP),10000)

collect:         ## passive CT collection (third-party estate, public data only)
	python -m collectors.passive_cert --targets config/targets.yaml -v

aggregate:       ## rebuild sector aggregates from the local raw store
	python -m collectors.passive_cert --aggregate-only

score:           ## HNDL scoring, sector level
	python scoring/hndl_score.py --from-store

capability:      ## resolve PQC capability from a software inventory export (INVENTORY=path)
	python inventory/pqc_capability.py --inventory $(INVENTORY)

report:          ## render docs/report.md from committed aggregates
	python reporting/build_report.py

handshake:       ## active probe, allowlisted hosts only, requires OpenSSL >= 3.5
	python active/handshake_demo.py --allowlist config/reference_hosts.yaml

test:            ## unit tests, no network
	python -m pytest tests/ -q

lint-sigma:      ## structural validation of the Sigma pack (needs pysigma)
	python tests/validate_sigma.py

lint-disclosure: ## scan committed artefacts for host identifiers
	python tests/lint_disclosure.py

validate:        ## scoring config: saturation, floors, weights, bands
	python scoring/hndl_score.py --validate-config

verify: test lint-sigma validate lint-disclosure  ## everything CI runs
