"""Offline tests. No network, no external binaries required.

Certificates are generated in-process so the parser is tested against real DER,
not against a fixture that happens to match the parser's assumptions.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from collectors.certparse import parse_certificate
from collectors.store import HostStore, host_key
from scoring.hndl_score import load_config, score_subject


def _make_cert(key, cn: str, days: int, sig_hash=hashes.SHA256()):
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    )
    cert = builder.sign(key, sig_hash)
    return cert.public_bytes(serialization.Encoding.PEM)


def test_rsa_certificate_dimensions():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = _make_cert(key, "rsa.test", days=90)
    rec = parse_certificate(pem).to_dict()

    assert rec["parse_error"] is None
    assert rec["key_algorithm"] == "RSA"
    assert rec["key_parameter"] == 2048
    assert rec["key_quantum_vulnerable"] is True
    assert rec["signature_quantum_vulnerable"] is True
    assert rec["validity_days"] == 90
    assert rec["valid_beyond_2030_milestone"] is False
    assert rec["san_dns"] == ["rsa.test"]
    assert rec["provenance"] == "measured"


def test_ec_certificate_and_long_validity_flags_milestone():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = _make_cert(key, "ec.test", days=365 * 12)
    rec = parse_certificate(pem).to_dict()

    assert rec["key_algorithm"] == "EC"
    assert rec["key_parameter"] == "secp256r1"
    assert rec["key_quantum_vulnerable"] is True
    assert rec["valid_beyond_2030_milestone"] is True


def test_parser_never_raises_on_garbage():
    rec = parse_certificate(b"not a certificate").to_dict()
    assert rec["parse_error"]
    assert rec["key_algorithm"] is None


def test_store_is_atomic_and_idempotent(tmp_path: Path):
    store = HostStore(tmp_path, ttl_seconds=3600)
    assert store.is_fresh("example.com") is False
    store.write("example.com", {"host": "example.com", "certificates": []})
    assert store.is_fresh("example.com") is True
    assert store.read("example.com")["host"] == "example.com"
    # no temp files survive a successful write
    assert list(tmp_path.glob("*.tmp")) == []
    assert host_key("Example.COM/../etc") == "example.com_.._etc"


def test_store_treats_corrupt_file_as_absent(tmp_path: Path):
    store = HostStore(tmp_path)
    p = store.path_for("broken.test")
    p.write_text("{ truncated", encoding="utf-8")
    assert store.read("broken.test") is None


@pytest.fixture(scope="module")
def cfg():
    return load_config()


def test_score_orders_sectors_by_confidentiality_horizon(cfg):
    base = {
        "key_quantum_vulnerable": True,
        "signature_quantum_vulnerable": True,
        "valid_beyond_2030_milestone": False,
        "validity_days": 90,
    }
    health = score_subject({**base, "sector": "healthcare"}, cfg)
    marketing = score_subject({**base, "sector": "marketing"}, cfg)

    assert health["score"] > marketing["score"]
    assert health["exposure_years_beyond_milestone"] > marketing["exposure_years_beyond_milestone"]
    assert health["components"]["horizon_pressure"]["provenance"] == "assumption"


def test_pqc_material_scores_lower_than_classical(cfg):
    classical = score_subject(
        {"sector": "finance", "key_quantum_vulnerable": True,
         "signature_quantum_vulnerable": True, "valid_beyond_2030_milestone": True,
         "validity_days": 398}, cfg)
    pqc = score_subject(
        {"sector": "finance", "key_quantum_vulnerable": False,
         "signature_quantum_vulnerable": False, "valid_beyond_2030_milestone": False,
         "validity_days": 90}, cfg)
    assert pqc["score"] < classical["score"]
    assert classical["band"] in {"moderate", "elevated", "high"}


def test_score_is_bounded_and_contributions_sum(cfg):
    s = score_subject({"sector": "healthcare", "key_quantum_vulnerable": True,
                       "signature_quantum_vulnerable": True,
                       "valid_beyond_2030_milestone": True, "validity_days": 3650}, cfg)
    assert 0.0 <= s["score"] <= 1.0
    total = sum(c["contribution"] for c in s["components"].values())
    assert abs(total - s["score"]) < 1e-3


def test_no_hardcoded_weights_in_scoring_module():
    """Weights must come from config. Guard against drift back into the code."""
    src = (REPO_ROOT / "scoring" / "hndl_score.py").read_text(encoding="utf-8")
    assert 'cfg["weights"]' in src
    for suspicious in ("0.30", "0.15", "healthcare\": 30"):
        assert suspicious not in src


def test_handshake_refuses_non_allowlisted_target(tmp_path: Path, capsys):
    from active import handshake_demo

    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("self: []\nreference:\n  - cloudflare.com\n", encoding="utf-8")
    rc = handshake_demo.main(
        ["--allowlist", str(allowlist), "--host", "some-bank.example", "--openssl", "openssl"]
    )
    # 2 = preflight (openssl too old here), 3 = refused target.
    # Either way the probe must not return success for a non-allowlisted host.
    assert rc in (2, 3)


def test_aggregate_suppresses_small_buckets(tmp_path: Path, monkeypatch):
    from collectors import passive_cert

    raw = tmp_path / "raw"
    agg = tmp_path / "agg"
    monkeypatch.setattr(passive_cert, "RAW_DIR", raw)
    monkeypatch.setattr(passive_cert, "AGG_DIR", agg)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store = HostStore(raw)
    for i in range(3):
        pem = _make_cert(key, f"h{i}.finance.test", days=90)
        store.write(f"h{i}.finance.test", {
            "host": f"h{i}.finance.test", "sector": "finance",
            "certificates": [parse_certificate(pem).to_dict()],
        })

    out = passive_cert.aggregate(min_bucket=5)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["sectors"] == {}
    assert "finance" in payload["disclosure_policy"]["suppressed_sectors"]

    out = passive_cert.aggregate(min_bucket=3)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["sectors"]["finance"]["hosts_observed"] == 3
    assert payload["sectors"]["finance"]["key_algorithms"]["RSA-2048"] == 3
    # no host identifiers survive aggregation
    assert "finance.test" not in json.dumps(payload["sectors"])
