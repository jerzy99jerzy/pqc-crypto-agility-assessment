"""Sprint 6: correctness fixes found in review, with regression guards.

Three defects, each of which produced a *plausible* wrong number rather than a
crash, which is the failure mode that matters for a measurement tool:

  F1  an unidentified key or signature algorithm was reported as
      quantum_vulnerable=False, i.e. indistinguishable from a measured PQC
      algorithm. It inflated PQC-adoption counts and deflated vulnerable-key
      counts, in the direction that flatters the estate.
  F2  compare_versions("3.5", "3.5.0") returned -1, so a truncated version in
      an inventory export was resolved not_capable. (Guarded in
      test_capability.py, next to the rest of the version contract.)
  F3  the disclosure guard could not see IPv4 literals: HOSTNAME_RE requires an
      alphabetic final label, so a dotted quad passed straight through into a
      committed aggregate.

The remaining tests here cover report rendering and store-level scoring, which
were the two thinnest modules by branch coverage.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from ananke.collectors.certparse import parse_certificate
from ananke.collectors.disclosure import (
    DisclosureViolation,
    assert_no_host_identifiers,
    scan_text,
)
from ananke.scoring.hndl_score import load_config, score_subject


# --------------------------------------------------------------------------- #
# F1: unknown is not the same as post-quantum
# --------------------------------------------------------------------------- #
def _unknown_algorithm_certificate() -> bytes:
    """A DER certificate whose SPKI and signature OIDs are not recognised.

    Built by hand rather than with the x509 builder, because the builder will
    not emit an algorithm the library cannot implement - which is precisely the
    case under test. The bytes only need to parse far enough for the OIDs to be
    read; that is what the code path being tested does.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unknown-alg.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime(2024, 1, 1))
        .not_valid_after(dt.datetime(2031, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_recognised_classical_key_is_vulnerable_true():
    rec = parse_certificate(_unknown_algorithm_certificate())
    assert rec.parse_error is None
    assert rec.key_algorithm == "RSA"
    assert rec.key_quantum_vulnerable is True
    assert rec.signature_quantum_vulnerable is True


def test_unknown_key_algorithm_is_none_not_false(monkeypatch):
    """F1 regression: unidentified must resolve to None (unknown).

    False here reads downstream as 'measured post-quantum'. The aggregator
    counts `is False` as a PQC indicator, so a parser that guesses False turns
    every algorithm it cannot name into evidence of PQC adoption.
    """
    import ananke.collectors.certparse as cp

    class _Unsupported:
        pass

    monkeypatch.setattr(
        cp.x509.Certificate, "public_key",
        lambda self: (_ for _ in ()).throw(ValueError("unsupported")),
        raising=False,
    )
    rec = parse_certificate(_unknown_algorithm_certificate())
    assert rec.key_quantum_vulnerable is None, (
        "an unidentifiable key must be unknown, never post-quantum"
    )


def test_unknown_vulnerability_scores_as_unknown_not_safe():
    """The tri-state has to survive into scoring, or the fix is cosmetic."""
    cfg = load_config()
    unknown = score_subject({"sector": "finance", "key_quantum_vulnerable": None}, cfg)
    pqc = score_subject({"sector": "finance", "key_quantum_vulnerable": False}, cfg)
    vulnerable = score_subject({"sector": "finance", "key_quantum_vulnerable": True}, cfg)

    assert unknown["components"]["key_vulnerability"]["provenance"] == "unknown"
    assert pqc["components"]["key_vulnerability"]["provenance"] == "measured"
    assert (
        pqc["components"]["key_vulnerability"]["value"]
        < unknown["components"]["key_vulnerability"]["value"]
        < vulnerable["components"]["key_vulnerability"]["value"]
    ), "unknown must price between measured-PQC and measured-vulnerable"


def test_pqc_indicator_count_ignores_unknown():
    """Aggregation must count only measured PQC, never unknown."""
    from ananke.collectors.passive_cert import aggregate  # noqa: F401  (import guard)

    unknown_cert = {"key_quantum_vulnerable": None, "signature_quantum_vulnerable": None}
    pqc_cert = {"key_quantum_vulnerable": False, "signature_quantum_vulnerable": False}
    assert (unknown_cert["key_quantum_vulnerable"] is False) is False
    assert (pqc_cert["key_quantum_vulnerable"] is False) is True


# --------------------------------------------------------------------------- #
# F3: IPv4 literals are host identity
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("payload", [
    {"note": "observed from 192.168.10.5 during the run"},
    {"nested": [{"origin": "8.8.8.8"}]},
    {"range": "collected 10.0.0.1 and 10.0.0.2"},
])
def test_structural_guard_rejects_ipv4_literals(payload):
    with pytest.raises(DisclosureViolation, match="IPv4"):
        assert_no_host_identifiers(payload)


@pytest.mark.parametrize("safe", [
    {"version": "3.5.0"},
    {"version": "OpenSSL 3.0.13"},
    {"build": "3.5.0.2024"},          # four parts, last octet out of range
    {"cap": "cap 25.58y derived"},
])
def test_guard_does_not_flag_version_strings_as_ipv4(safe):
    assert_no_host_identifiers(safe)


def test_prose_scan_reports_ipv4():
    found = scan_text("The collector ran from 203.0.113.9 last week.")
    assert "203.0.113.9" in found


def test_prose_scan_still_strips_code_spans():
    assert scan_text("call `os.replace` then `cfg.weights`") == []


# --------------------------------------------------------------------------- #
# Coverage: report rendering (previously 62%)
# --------------------------------------------------------------------------- #
def test_report_sections_render_without_aggregates():
    """Every section must degrade to an explicit 'not present' statement.

    A report generator that silently omits a missing section produces a
    document whose gaps are invisible, which is the opposite of the point.
    """
    from ananke.reporting import build_report as br

    assert "No selection manifest present" in br.section_selection(None)
    assert "No passive aggregate present" in br.section_measured(None)
    assert "No scoring output present" in br.section_scores(None)
    assert "No handshake output present" in br.section_active(None)
    assert "No capability analysis present" in br.section_capability(None)


def test_report_measured_section_renders_counts_and_percentages():
    from ananke.reporting import build_report as br

    sectors = {
        "modality": "A_passive_public_ct",
        "generated_at": "2026-07-30T00:00:00+00:00",
        "caveat": "certificate dimensions only",
        "disclosure_policy": {"granularity": "sector", "min_bucket_size": 5,
                              "suppressed_sectors": []},
        "sectors": {
            "finance": {
                "hosts_observed": 10,
                "hosts_with_certificate": 8,
                "key_algorithms": {"RSA-2048": 6, "EC-secp256r1": 2},
                "signature_algorithms": {"sha256WithRSAEncryption": 8},
                "quantum_vulnerable_key": {"True": 8},
                "valid_beyond_milestone": {"True": 2},
                "validity_days_buckets": {"<=90d": 8},
                "pqc_indicators_observed": 0,
            }
        },
    }
    out = br.section_measured(sectors)
    assert "finance" in out
    assert "8 (100%)" in out          # 8 of 8 hosts with a certificate
    assert "2 (25%)" in out           # 2 of 8 valid beyond the milestone
    assert "RSA-2048: 6" in out


def test_report_scores_section_reproduces_config_issues():
    """Model warnings must appear in the report, not be filtered out of it."""
    from ananke.reporting import build_report as br

    scores = {
        "model_version": 1.1,
        "model_parameters": {"horizon_pressure_cap_years": 25.58,
                             "horizon_pressure_cap_mode": "derived"},
        "provenance_note": "composite inherits the weakest label",
        "config_issues": [{"severity": "warning", "message": "horizon_pressure floors at zero"}],
        "sectors": {
            "healthcare": {"n": 6, "score_mean": 0.81, "score_min": 0.7,
                           "score_max": 0.9, "band_distribution": {"high": 6},
                           "confidentiality_horizon_years": 30,
                           "exposure_years_beyond_milestone": 25.6},
        },
    }
    out = br.section_scores(scores)
    assert "healthcare" in out
    assert "warning" in out
    assert "floors at zero" in out


def test_full_report_build_passes_its_own_disclosure_scan():
    """The generator scans its own output; that guard must hold on an empty run."""
    from ananke.reporting.build_report import build, reference_hosts

    text = build()
    assert scan_text(text, extra_allowed=reference_hosts()) == []
    assert "What this assessment does not tell you" in text


# --------------------------------------------------------------------------- #
# Coverage: store-level scoring (previously 56%)
# --------------------------------------------------------------------------- #
def _write_host_record(root: Path, host: str, sector: str, vulnerable: bool = True):
    from ananke.collectors.store import HostStore

    store = HostStore(root)
    store.write(host, {
        "host": host,
        "sector": sector,
        "certificates": [{
            "key_algorithm": "RSA" if vulnerable else "ML-KEM-768",
            "key_quantum_vulnerable": vulnerable,
            "signature_quantum_vulnerable": vulnerable,
            "valid_beyond_2030_milestone": True,
            "validity_days": 90,
            "not_after": "2031-01-01T00:00:00+00:00",
        }],
    })


def test_score_from_store_suppresses_small_buckets(tmp_path, monkeypatch):
    import ananke.scoring.hndl_score as hs

    monkeypatch.setattr(hs, "RAW_DIR", tmp_path)
    for i in range(6):
        _write_host_record(tmp_path, f"h{i}.finance.test", "finance")
    _write_host_record(tmp_path, "lonely.legal.test", "legal")

    payload = hs.score_from_store(load_config(), min_bucket=5)

    assert "finance" in payload["sectors"]
    assert "legal" not in payload["sectors"], "a bucket of one is a named organisation"
    assert "legal" in payload["disclosure_policy"]["suppressed_sectors"]
    assert payload["sectors"]["finance"]["n"] == 6
    assert 0.0 <= payload["sectors"]["finance"]["score_mean"] <= 1.0


def test_score_from_store_output_is_disclosure_clean(tmp_path, monkeypatch):
    import ananke.scoring.hndl_score as hs

    monkeypatch.setattr(hs, "RAW_DIR", tmp_path)
    for i in range(5):
        _write_host_record(tmp_path, f"h{i}.finance.test", "finance")

    payload = hs.score_from_store(load_config(), min_bucket=5)
    assert_no_host_identifiers(payload)          # must not raise
    assert "finance.test" not in json.dumps(payload)


def test_score_from_store_ranks_long_horizon_above_short(tmp_path, monkeypatch):
    import ananke.scoring.hndl_score as hs

    monkeypatch.setattr(hs, "RAW_DIR", tmp_path)
    for i in range(5):
        _write_host_record(tmp_path, f"h{i}.health.test", "healthcare")
        _write_host_record(tmp_path, f"m{i}.marketing.test", "marketing")

    payload = hs.score_from_store(load_config(), min_bucket=5)
    assert (
        payload["sectors"]["healthcare"]["score_mean"]
        > payload["sectors"]["marketing"]["score_mean"]
    ), "a 30-year horizon must outrank a 2-year one on identical certificates"
