"""Sprint 9: the source seam, and the regime a source drags behind it.

Until now the collector was welded to Certificate Transparency, which made a
first-party engagement impossible: an operator handing over their own
certificates had nowhere to put them. Adding a second source is easy. The part
worth testing is what changes with it.

Two invariants carry the sprint:

1. A source declares its own regime, and the aggregate reports that regime
   rather than a constant. Certificate Transparency is `measured`, because the
   log is a public record nobody in the transaction curated. An operator's dump
   is `reported`: each certificate in it is still parsed by us, but the
   completeness of the set is the client's claim.

2. Minimum bucket size may be relaxed only for a first-party estate, and only
   because a source said so. Suppression exists to stop a third party being
   identified through a sector of one; a paying operator has nobody to be
   protected from. There is deliberately no flag that turns it off for CT data,
   and `test_no_argument_relaxes_suppression_for_ct_data` is the guard on that.
"""
from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from collectors import passive_cert
from collectors.passive_cert import MixedModalityError, _regime, aggregate
from collectors.sources import CrtShSource, LocalPemSource


def _cert(cn: str | None, sans: list[str] | None = None, days: int = 365) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn else []
    name = x509.Name(attrs)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def _store(tmp_path, monkeypatch):
    raw = tmp_path / "raw"; raw.mkdir()
    agg = tmp_path / "agg"; agg.mkdir()
    monkeypatch.setattr(passive_cert, "RAW_DIR", raw)
    monkeypatch.setattr(passive_cert, "AGG_DIR", agg)
    return raw


def _record(host, sector, modality):
    return {
        "host": host, "sector": sector, "modality": modality,
        "certificates": [{
            "key_algorithm": "RSA", "key_parameter": 2048,
            "key_quantum_vulnerable": True, "signature_algorithm": "sha256WithRSA",
            "valid_beyond_2030_milestone": False, "validity_days": 90,
        }],
    }


# --------------------------------------------------------------------------- #
# LocalPemSource
# --------------------------------------------------------------------------- #
def test_host_comes_from_the_certificate_not_the_filename(tmp_path):
    """A filename is a label somebody typed. The subject is part of the signed
    object, so that is what identifies the host."""
    (tmp_path / "wrong-name.pem").write_bytes(_cert("gateway.operator.test"))

    records = list(LocalPemSource(tmp_path, "logistics").iter_records())

    assert [r["host"] for r in records] == ["gateway.operator.test"]
    assert records[0]["certificates"][0]["source_file"] == "wrong-name.pem"


def test_wildcard_and_case_are_normalised(tmp_path):
    (tmp_path / "a.pem").write_bytes(_cert("*.Operator.TEST"))
    records = list(LocalPemSource(tmp_path, "logistics").iter_records())
    assert records[0]["host"] == "operator.test"


def test_certificates_for_one_host_land_in_one_record(tmp_path):
    """An operator's dump routinely holds several certificates per host."""
    (tmp_path / "current.pem").write_bytes(_cert("gw.operator.test", days=90))
    (tmp_path / "expiring.crt").write_bytes(_cert("gw.operator.test", days=400))

    records = list(LocalPemSource(tmp_path, "logistics").iter_records())

    assert len(records) == 1
    assert len(records[0]["certificates"]) == 2


def test_a_certificate_without_a_subject_is_not_given_an_invented_host(tmp_path):
    (tmp_path / "mystery.der").write_bytes(_cert(None))
    records = list(LocalPemSource(tmp_path, "logistics").iter_records())
    assert records[0]["host"] == "unidentified-mystery"


def test_san_is_used_when_the_subject_is_empty(tmp_path):
    (tmp_path / "s.pem").write_bytes(_cert(None, sans=["edge.operator.test"]))
    records = list(LocalPemSource(tmp_path, "logistics").iter_records())
    assert records[0]["host"] == "edge.operator.test"


def test_non_certificate_files_are_ignored(tmp_path):
    (tmp_path / "notes.txt").write_text("not a certificate", encoding="utf-8")
    (tmp_path / "real.pem").write_bytes(_cert("gw.operator.test"))
    assert len(list(LocalPemSource(tmp_path, "logistics").iter_records())) == 1


def test_source_provenance_is_reported_but_the_certificate_stays_measured(tmp_path):
    """The client asserts the set is complete; we still parse each file
    ourselves, so the fields are measured and the set is not."""
    (tmp_path / "a.pem").write_bytes(_cert("gw.operator.test"))
    src = LocalPemSource(tmp_path, "logistics")
    record = next(iter(src.iter_records()))

    assert src.provenance == "reported"
    assert record["provenance"] == "reported"
    assert record["certificates"][0]["provenance"] == "measured"


def test_offline_source_declares_first_party_and_ct_does_not():
    assert LocalPemSource("/tmp", "x").first_party is True
    assert CrtShSource({}, client=None).first_party is False


# --------------------------------------------------------------------------- #
# Regime resolution and suppression
# --------------------------------------------------------------------------- #
def test_first_party_estate_survives_a_sector_smaller_than_min_bucket(tmp_path, monkeypatch):
    """One operator is one sector. Suppressing it would delete the deliverable
    while protecting nobody."""
    raw = _store(tmp_path, monkeypatch)
    for i in range(2):
        passive_cert.HostStore(raw).write(f"h{i}", _record(f"h{i}", "logistics", "first_party_offline"))

    payload = _read(aggregate(min_bucket=5))

    assert "logistics" in payload["sectors"]
    assert payload["provenance"] == "reported"
    assert payload["modality"] == "D_first_party_offline"
    assert payload["disclosure_policy"]["first_party_estate"] is True
    assert payload["disclosure_policy"]["min_bucket_size"] == 1
    # First-party status changes the threshold, not what the file contains.
    assert payload["disclosure_policy"]["granularity"] == "sector"
    assert all("host" not in s for s in payload["sectors"].values())


def test_no_argument_relaxes_suppression_for_ct_data(tmp_path, monkeypatch):
    """The security property of the sprint. Third-party sectors below the
    threshold are dropped no matter what is passed in."""
    raw = _store(tmp_path, monkeypatch)
    for i in range(2):
        passive_cert.HostStore(raw).write(f"h{i}", _record(f"h{i}", "finance", "passive"))

    payload = _read(aggregate(min_bucket=5))

    assert payload["sectors"] == {}
    assert payload["disclosure_policy"]["suppressed_sectors"] == ["finance"]
    assert payload["disclosure_policy"]["first_party_estate"] is False
    assert payload["provenance"] == "measured"


def test_a_store_mixing_modalities_refuses_to_aggregate(tmp_path, monkeypatch):
    """"40% RSA" across a public sample and across one operator's estate are
    different statements. Summing them produces a number with no referent."""
    raw = _store(tmp_path, monkeypatch)
    passive_cert.HostStore(raw).write("a", _record("a", "finance", "passive"))
    passive_cert.HostStore(raw).write("b", _record("b", "logistics", "first_party_offline"))

    with pytest.raises(MixedModalityError):
        aggregate(min_bucket=1)


def test_an_unknown_modality_tag_fails_to_the_conservative_row():
    modality, provenance, first_party = _regime([{"modality": "something-new"}])
    assert first_party is False, "an unrecognised tag must not unlock suppression"
    assert provenance == "measured"
    assert modality == "something-new"


def test_a_store_written_before_sprint_9_still_aggregates(tmp_path, monkeypatch):
    """Records from earlier versions carry no modality tag at all."""
    raw = _store(tmp_path, monkeypatch)
    for i in range(5):
        rec = _record(f"h{i}", "finance", "passive")
        rec.pop("modality")
        passive_cert.HostStore(raw).write(f"h{i}", rec)

    payload = _read(aggregate(min_bucket=5))
    assert payload["modality"] == "A_passive_public_ct"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_local_pem_requires_a_directory_and_a_sector(tmp_path, capsys):
    """A certificate does not carry the operator's sector, so it must be given
    rather than guessed."""
    assert passive_cert.main(["--source", "local-pem"]) == 2
    assert passive_cert.main(["--source", "local-pem", "--pem-dir", str(tmp_path)]) == 2


def _read(path):
    import json
    return json.loads(path.read_text(encoding="utf-8"))
