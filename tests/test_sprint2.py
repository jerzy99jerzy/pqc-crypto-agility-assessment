"""Sprint 2 tests: scoring cap derivation, disclosure enforcement, selection, report.

No network, no external binaries.
"""

from __future__ import annotations

import copy
import csv
import datetime as dt
import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from collectors.disclosure import (  # noqa: E402
    DisclosureViolation,
    assert_bucket_sizes,
    assert_no_host_identifiers,
    scan_text,
)
from collectors.select_targets import classify, matching_rules, select  # noqa: E402
from scoring.hndl_score import (  # noqa: E402
    exposure_years,
    horizon_pressure_cap,
    load_config,
    milestone_date,
    score_subject,
    validate_config,
)


@pytest.fixture(scope="module")
def cfg():
    return load_config()


# --- scoring: saturation regression ----------------------------------------

def test_derived_cap_prevents_saturation(cfg):
    """The sprint 1 defect: cap 20 while the longest horizon was 30."""
    today = dt.date.today()
    milestone = milestone_date(cfg)
    cap, mode = horizon_pressure_cap(cfg, today)
    assert mode == "derived"
    for sector, horizon in cfg["confidentiality_horizon_years"]["by_sector"].items():
        assert exposure_years(horizon, today, milestone) <= cap, sector


def test_longest_horizon_sectors_are_distinguishable(cfg):
    base = {"key_quantum_vulnerable": True, "signature_quantum_vulnerable": True,
            "valid_beyond_2030_milestone": False, "validity_days": 90}
    healthcare = score_subject({**base, "sector": "healthcare"}, cfg)   # 30y
    government = score_subject({**base, "sector": "government"}, cfg)   # 25y
    insurance = score_subject({**base, "sector": "insurance"}, cfg)     # 20y
    scores = [healthcare["score"], government["score"], insurance["score"]]
    assert scores == sorted(scores, reverse=True)
    assert len(set(scores)) == 3, "long-horizon sectors collapsed onto one score again"


def test_fixed_cap_saturation_is_reported_as_error(cfg):
    bad = copy.deepcopy(cfg)
    bad["parameters"]["horizon_pressure_cap_years"] = 20
    issues = validate_config(bad)
    errors = [i for i in issues if i["severity"] == "error"]
    assert errors and "saturates" in errors[0]["message"]


def test_clean_config_has_no_errors(cfg):
    assert [i for i in validate_config(cfg) if i["severity"] == "error"] == []


def test_cap_renormalises_as_the_milestone_approaches(cfg):
    early, _ = horizon_pressure_cap(cfg, dt.date(2026, 1, 1))
    late, _ = horizon_pressure_cap(cfg, dt.date(2029, 1, 1))
    assert late > early


def test_bad_band_order_is_an_error(cfg):
    bad = copy.deepcopy(cfg)
    bad["bands"] = [{"name": "high", "min": 0.75}, {"name": "low", "min": 0.0}]
    assert any(i["severity"] == "error" and "ascending" in i["message"]
               for i in validate_config(bad))


# --- disclosure guard -------------------------------------------------------

def test_guard_rejects_forbidden_keys():
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"sectors": {"finance": {"host": "x"}}})


def test_guard_rejects_hostname_strings():
    with pytest.raises(DisclosureViolation) as exc:
        assert_no_host_identifiers({"note": "sample included mojbank.pl"})
    assert "mojbank.pl" in str(exc.value)


def test_guard_allows_filenames_and_versions():
    assert_no_host_identifiers({
        "source": "crt.sh",
        "config": "weights.yaml",
        "ranking": "tranco_2026_07.csv",
        "openssl_version": "3.5.0",
    })


def test_guard_does_not_treat_cctld_extensions_as_filenames():
    """.sh .py .md .io are live ccTLDs; allowing them by extension is a blind spot."""
    for host in ("payments.sh", "acme.io", "shop.md"):
        with pytest.raises(DisclosureViolation):
            assert_no_host_identifiers({"note": f"observed {host}"})


def test_guard_rejects_certificate_fingerprints():
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"sha256": "ab" * 32})


def test_bucket_guard_rejects_small_sectors():
    with pytest.raises(DisclosureViolation):
        assert_bucket_sizes({"finance": 9, "media": 2}, minimum=5)


def test_scan_text_permits_declared_reference_hosts():
    text = "One handshake to cloudflare.com and one to bank-x.pl"
    assert scan_text(text, extra_allowed={"cloudflare.com"}) == ["bank-x.pl"]


# --- target selection -------------------------------------------------------

RULES = {
    "energy": {"contains": ["gazow", "gaz-"], "exclude": ["gazeta"]},
    "media": {"contains": ["gazeta"]},
    "finance": {"contains": ["bank"]},
    "government": {"suffix": [".gov.pl"]},
}


def test_classification_collision_is_detected():
    colliding = {"energy": {"contains": ["gaz"]}, "media": {"contains": ["gazeta"]}}
    hits = matching_rules("gazeta.pl", colliding)
    assert {s for s, _ in hits} == {"energy", "media"}


def test_exclude_resolves_the_collision():
    hits = matching_rules("gazeta.pl", RULES)
    assert {s for s, _ in hits} == {"media"}
    assert classify("gazeta.pl", RULES)[0] == "media"


def test_classification_records_the_winning_rule():
    sector, rule = classify("mojbank.pl", RULES)
    assert sector == "finance"
    assert rule == "finance.contains:bank"


def test_suffix_rule_and_unclassified():
    assert classify("urzad.gov.pl", RULES)[0] == "government"
    assert classify("nothing-matches.pl", RULES) == ("unclassified", "none")


def test_selection_manifest_carries_provenance_and_no_domains(tmp_path: Path):
    ranking = tmp_path / "ranking.csv"
    with open(ranking, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for i, d in enumerate(["mojbank1.pl", "mojbank2.pl", "gazeta1.pl", "x.com"], start=1):
            w.writerow([i, d])
    rules = tmp_path / "rules.yaml"
    rules.write_text(yaml.safe_dump({"rules": RULES}), encoding="utf-8")

    sectors, manifest = select(ranking, rules, suffix=".pl", top=None, min_bucket=5)

    assert sectors["finance"] == ["mojbank1.pl", "mojbank2.pl"]
    assert manifest["source"]["rows_in_scope"] == 3          # .com filtered out
    assert len(manifest["source"]["file_sha256"]) == 64
    assert manifest["undersized_sectors"] == ["finance", "media"]
    # the manifest is committed, so it must survive the guard
    assert_no_host_identifiers(manifest)
    assert "mojbank1.pl" not in json.dumps(manifest)


# --- report builder ---------------------------------------------------------

def test_report_builder_refuses_leaked_hostnames(monkeypatch, tmp_path: Path):
    from reporting import build_report

    monkeypatch.setattr(build_report, "AGG_DIR", tmp_path)
    (tmp_path / "sectors.json").write_text(json.dumps({
        "modality": "A_passive_public_ct",
        "generated_at": "2026-07-29T00:00:00+00:00",
        "caveat": "leaked mojbank.pl into prose",
        "disclosure_policy": {"granularity": "sector", "min_bucket_size": 5,
                              "suppressed_sectors": []},
        "sectors": {"finance": {
            "hosts_observed": 8, "hosts_with_certificate": 8,
            "key_algorithms": {"RSA-2048": 8}, "signature_algorithms": {},
            "quantum_vulnerable_key": {"True": 8},
            "valid_beyond_2030_milestone": {"False": 8},
            "validity_days_buckets": {}, "pqc_indicators_observed": 0}},
    }), encoding="utf-8")

    with pytest.raises(DisclosureViolation):
        build_report.main(["--out", str(tmp_path / "report.md")])
    assert not (tmp_path / "report.md").exists(), "report was written despite a leak"


def test_report_states_missing_denominator(monkeypatch, tmp_path: Path):
    from reporting import build_report

    monkeypatch.setattr(build_report, "AGG_DIR", tmp_path)
    out = tmp_path / "report.md"
    assert build_report.main(["--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "No selection manifest present" in text
    assert "percentage without a stated denominator is not a finding" in text


def test_prose_scan_ignores_code_spans_but_not_prose():
    doc = "Atomic writes use `os.replace`, and the sample included mojbank.pl."
    assert scan_text(doc) == ["mojbank.pl"]
    assert scan_text("only `cfg.weights` and `ssl.log` here") == []


def test_strict_guard_has_no_code_span_exemption():
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"note": "`mojbank.pl`"})
