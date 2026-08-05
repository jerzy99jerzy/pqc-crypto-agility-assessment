"""Sprint 11: the milestone becomes configuration, the aggregate grows a
decision layer, and the report learns to render HTML through the same gate.

Three properties carry the sprint:

1. The decision split (self-resolving vs intervention) is recomputed from
   expiry dates against the milestone passed to aggregation, never read from
   the stored boolean - so a store collected under one milestone reclassifies
   correctly under another, without recollecting.
2. Nothing identity-shaped reaches the aggregate through the new counters. The
   issuer distribution was the near-miss: on a self-signed certificate the
   issuer IS the subject, so counting issuer CNs walks host identity straight
   into committed output. Caught by the sprint 2 suppression test during
   development; pinned here.
3. The HTML renderer escapes at interpolation, embeds dates only, and its
   output passes the disclosure guard with code and data scanned separately:
   script bodies are code and are exempt, string literals inside them are data
   and are not.
"""
from __future__ import annotations

import datetime as dt
import json

import pytest

from ananke.collectors import passive_cert
from ananke.collectors.passive_cert import aggregate
from ananke.config import DEFAULT_MILESTONE, load_milestone
from ananke.reporting.build_report import _scan_embedded_data, _strip_active_blocks
from ananke.reporting.html_report import esc, render_html


def _store(tmp_path, monkeypatch):
    raw = tmp_path / "raw"; raw.mkdir(parents=True, exist_ok=True)
    agg = tmp_path / "agg"; agg.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(passive_cert, "RAW_DIR", raw)
    monkeypatch.setattr(passive_cert, "AGG_DIR", agg)
    return raw


def _record(host, not_after, validity_days=365, issuer_o=None, issuer_cn=None):
    return {
        "host": host, "sector": "logistics", "modality": "first_party_offline",
        "certificates": [{
            "key_algorithm": "RSA", "key_parameter": 2048,
            "key_quantum_vulnerable": True,
            "signature_algorithm": "sha256WithRSA",
            "valid_beyond_milestone": None,  # deliberately absent/None: split
            "not_after": not_after,          # must come from the date
            "validity_days": validity_days,
            "issuer_o": issuer_o, "issuer_cn": issuer_cn,
        }],
    }


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# configurable milestone
# --------------------------------------------------------------------------- #
def test_default_milestone_is_the_eu_roadmap_date():
    assert load_milestone() == dt.date(2030, 12, 31)


def test_milestone_reads_from_config(tmp_path):
    cfg = tmp_path / "w.yaml"
    cfg.write_text("milestone:\n  date: 2033-06-30\n", encoding="utf-8")
    assert load_milestone(cfg) == dt.date(2033, 6, 30)


def test_milestone_fails_soft_to_default(tmp_path):
    """A broken config must not stop a run: the default is itself a sourced
    regulatory date, not a guess."""
    cfg = tmp_path / "w.yaml"
    cfg.write_text("milestone:\n  date: not-a-date\n", encoding="utf-8")
    assert load_milestone(cfg) == DEFAULT_MILESTONE
    assert load_milestone(tmp_path / "absent.yaml") == DEFAULT_MILESTONE


def test_decision_split_moves_with_the_milestone(tmp_path, monkeypatch):
    """The same store, two milestones, two different plans - recomputed from
    dates, so no recollection is needed."""
    raw = _store(tmp_path, monkeypatch)
    passive_cert.HostStore(raw).write("a", _record("a", "2029-06-01T00:00:00+00:00"))
    passive_cert.HostStore(raw).write("b", _record("b", "2031-06-01T00:00:00+00:00"))
    passive_cert.HostStore(raw).write("c", _record("c", "2035-06-01T00:00:00+00:00"))

    strict = _read(aggregate(min_bucket=1, milestone=dt.date(2028, 12, 31)))
    assert strict["sectors"]["logistics"]["intervention_required"] == 3
    assert strict["milestone"]["date"] == "2028-12-31"

    loose = _read(aggregate(min_bucket=1, milestone=dt.date(2033, 12, 31)))
    s = loose["sectors"]["logistics"]
    assert s["self_resolving_via_rotation"] == 2
    assert s["intervention_required"] == 1
    assert s["intervention_expiry_years"] == {"2035": 1}


def test_rotation_stats_are_counters_not_hosts(tmp_path, monkeypatch):
    raw = _store(tmp_path, monkeypatch)
    for host, days in (("a", 90), ("b", 400), ("c", 3650)):
        passive_cert.HostStore(raw).write(
            host, _record(host, "2029-01-01T00:00:00+00:00", validity_days=days))
    payload = _read(aggregate(min_bucket=1))
    stats = payload["sectors"]["logistics"]["rotation_stats"]
    assert stats["median"] == 400 and stats["min"] == 90 and stats["max"] == 3650
    assert "validity_days_all" not in payload["sectors"]["logistics"], \
        "the raw list must never be emitted"
    assert payload["sectors"]["logistics"]["rotation_bands"] == {
        "<=100d": 1, "101-400d": 1, ">1100d": 1}


# --------------------------------------------------------------------------- #
# the issuer near-miss
# --------------------------------------------------------------------------- #
def test_self_signed_issuer_cn_does_not_reach_the_aggregate(tmp_path, monkeypatch):
    """On a self-signed certificate the issuer IS the subject. Counting issuer
    CNs published host identity; only an organisation name is counted, and a
    host-shaped one is bucketed as self-signed."""
    raw = _store(tmp_path, monkeypatch)
    passive_cert.HostStore(raw).write(
        "h", _record("h", "2029-01-01T00:00:00+00:00",
                     issuer_o=None, issuer_cn="gw.operator.internal"))
    passive_cert.HostStore(raw).write(
        "i", _record("i", "2029-01-01T00:00:00+00:00",
                     issuer_o="Example Trust Services", issuer_cn="Example CA 1"))
    payload = _read(aggregate(min_bucket=1))
    issuers = payload["sectors"]["logistics"]["issuers"]
    assert "gw.operator.internal" not in json.dumps(payload)
    assert issuers.get("(self-signed or unnamed)") == 1
    assert issuers.get("Example Trust Services") == 1


def test_host_shaped_issuer_o_is_also_dropped(tmp_path, monkeypatch):
    """Some appliances put a hostname in issuer O. Shape decides, not field."""
    raw = _store(tmp_path, monkeypatch)
    passive_cert.HostStore(raw).write(
        "h", _record("h", "2029-01-01T00:00:00+00:00",
                     issuer_o="mgmt.vendor-box.local"))
    payload = _read(aggregate(min_bucket=1))
    assert "vendor-box" not in json.dumps(payload)


# --------------------------------------------------------------------------- #
# html renderer
# --------------------------------------------------------------------------- #
def _minimal_sectors():
    return {
        "generated_at": "2026-08-05T00:00:00+00:00",
        "modality": "D_first_party_offline", "provenance": "reported",
        "milestone": {"date": "2030-12-31"},
        "disclosure_policy": {"first_party_estate": True},
        "sectors": {"logistics": {
            "hosts_observed": 2, "hosts_with_certificate": 2,
            "self_resolving_via_rotation": 1, "intervention_required": 1,
            "intervention_expiry_years": {"2033": 1},
            "rotation_bands": {"<=100d": 1, ">1100d": 1},
            "rotation_stats": {"median": 800, "min": 90, "max": 3650,
                               "rotations_before_milestone": 2.0},
            "valid_beyond_milestone": {"True": 1, "False": 1},
            "issuers": {"Example Trust Services": 2},
        }},
    }


def test_html_escapes_every_interpolated_value():
    """A sector name that somehow carries markup must render inert. The label
    is shape-validated upstream, but this renderer does not rely on that."""
    payload = _minimal_sectors()
    payload["sectors"] = {"logistics": payload["sectors"]["logistics"]}
    # simulate a hostile value arriving in a non-key position
    payload["modality"] = 'D<script>alert(1)</script>'
    html = render_html(payload, None)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_esc_covers_attribute_context():
    assert esc('a"b') == "a&quot;b"


def test_html_report_contains_no_external_references():
    html = render_html(_minimal_sectors(), None,
                       [{"nb": "2026-01-01", "na": "2033-01-01"}])
    assert 'src="http' not in html and 'href="http' not in html
    assert "@import" not in html


def test_chart_payload_is_dates_only():
    html = render_html(_minimal_sectors(), None,
                       [{"nb": "2026-01-01", "na": "2033-01-01",
                         "host": "leak.example"}])
    assert "leak.example" not in html, "renderer must drop unexpected fields"


def test_strip_active_blocks_keeps_prose_and_drops_code():
    doc = "<script>ms.value;Date.UTC(2030,0)</script><p>finding text</p>"
    stripped = _strip_active_blocks(doc)
    assert "finding text" in stripped and "Date.UTC" not in stripped


def test_embedded_data_scan_catches_a_smuggled_host():
    """Code is repository-reviewed and exempt; data is per-engagement and is
    not. A host identifier inside a string literal in a script must fail."""
    evil = ('<script>const CERTS=[{"nb":"2026-01-01",'
            '"na":"victim-bank.pl"}];</script>')
    assert "victim-bank.pl" in _scan_embedded_data(evil)
    clean = "<script>const x=Date.UTC(2030,0);ms.value;</script>"
    assert _scan_embedded_data(clean) == []
