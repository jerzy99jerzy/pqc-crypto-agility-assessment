"""Sprint 10: what an operator's dump looks like when somebody has an interest
in how the report reads.

The pattern is borrowed from the sibling repository `phantomatics`, where the
adversarial world is what actually validated the channel weights, and the clean
world only ever confirmed something nobody doubted. The same applies here. The
offline source shipped in v0.9.0 was tested against certificates this project
generated for itself. That proves the parser works. It proves nothing about what
happens when the directory was assembled by a party who would like a particular
number to come out.

Three worlds, from `ananke.fixture`:

`clean`     an estate as an inventory tool would like to find it
`partial`   adversary A3: every file genuine, the failing estate simply absent
`hostile`   filenames that contradict subjects, underscore-glued identity, an
            empty subject, and a file that is not a certificate

The load-bearing assertions are that the hostile world neither crashes the run
nor puts a host identifier into committed output, and that the partial world is
indistinguishable from the clean one on the data alone, which is exactly why the
label is `reported`.
"""
from __future__ import annotations

import json

import pytest

from ananke import fixture
from ananke.collectors import passive_cert
from ananke.collectors.disclosure import DisclosureViolation, assert_no_host_identifiers
from ananke.collectors.passive_cert import aggregate
from ananke.collectors.sources import LocalPemSource


@pytest.fixture
def world(tmp_path):
    def _build(name):
        out = tmp_path / name
        fixture.build(out, name)
        return out
    return _build


def _collect(monkeypatch, tmp_path, pem_dir, sector="logistics"):
    raw = tmp_path / "raw"; raw.mkdir(parents=True, exist_ok=True)
    agg = tmp_path / "agg"; agg.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(passive_cert, "RAW_DIR", raw)
    monkeypatch.setattr(passive_cert, "AGG_DIR", agg)
    passive_cert.collect(LocalPemSource(pem_dir, sector), ttl=0, force=True)
    return json.loads(aggregate(min_bucket=5).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# clean world: the baseline, and the finding it is supposed to surface
# --------------------------------------------------------------------------- #
def test_clean_world_surfaces_the_certificate_that_crosses_2030(world, tmp_path, monkeypatch):
    payload = _collect(monkeypatch, tmp_path, world("clean"))
    counts = payload["sectors"]["logistics"]["valid_beyond_milestone"]
    assert counts.get("True", 0) >= 1, "the long-lived certificate is the whole point"
    assert payload["provenance"] == "reported"


# --------------------------------------------------------------------------- #
# hostile world
# --------------------------------------------------------------------------- #
def test_hostile_world_does_not_crash_the_run(world, tmp_path, monkeypatch):
    """A file that is not a certificate must be recorded and stepped over."""
    payload = _collect(monkeypatch, tmp_path, world("hostile"))
    assert payload["sectors"]["logistics"]["hosts_observed"] >= 5


def test_a_lying_filename_does_not_decide_host_identity(world, tmp_path):
    """`gateway.operator.example.pem` carries a subject for a different party.
    Trusting the filename would put a third party's name in the store."""
    records = list(LocalPemSource(world("hostile"), "logistics").iter_records())
    hosts = {r["host"] for r in records}
    assert "finance-customer.example" in hosts
    assert "gateway.operator.example" not in hosts


def test_underscore_glued_identity_is_still_seen(world, tmp_path):
    """The v0.8.0 defect, arriving through the input path that did not exist
    when it was fixed."""
    records = list(LocalPemSource(world("hostile"), "logistics").iter_records())
    assert "prefix_bank.example" in {r["host"] for r in records}
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"note": "prefix_bank.example"})


def test_no_host_identifier_reaches_the_aggregate(world, tmp_path, monkeypatch):
    """The promise the project is published on, exercised against the worst
    input the fixture can build."""
    payload = _collect(monkeypatch, tmp_path, world("hostile"))
    blob = json.dumps(payload)
    for identifier in ("finance-customer", "prefix_bank", "legacy-edi", "operator.example"):
        assert identifier not in blob
    assert_no_host_identifiers(payload)


def test_an_unparseable_file_is_recorded_rather_than_dropped(world, tmp_path):
    records = list(LocalPemSource(world("hostile"), "logistics").iter_records())
    errors = [c for r in records for c in r["certificates"] if c.get("parse_error")]
    assert errors, "a truncated file must leave a trace, not vanish"


# --------------------------------------------------------------------------- #
# partial world: the adversary who is paying
# --------------------------------------------------------------------------- #
def test_a_convenient_dump_is_indistinguishable_from_a_complete_one(world, tmp_path, monkeypatch):
    """No property of the files reveals what was left out. This is the argument
    for the label, and the reason the label sits on the set."""
    partial = _collect(monkeypatch, tmp_path / "a", world("partial"))
    assert partial["sectors"]["logistics"]["valid_beyond_milestone"].get("True", 0) == 0
    assert partial["provenance"] == "reported"
    assert partial["disclosure_policy"]["first_party_estate"] is True


def test_every_certificate_stays_measured_while_the_set_is_reported(world, tmp_path):
    """The distinction is narrow and load-bearing: we parsed each file
    ourselves, so the fields are observed. Completeness is not."""
    records = list(LocalPemSource(world("partial"), "logistics").iter_records())
    assert all(r["provenance"] == "reported" for r in records)
    assert all(
        c["provenance"] == "measured"
        for r in records for c in r["certificates"] if not c.get("parse_error")
    )


# --------------------------------------------------------------------------- #
# the generator itself
# --------------------------------------------------------------------------- #
def test_every_world_builds(tmp_path):
    for name in fixture.WORLDS:
        assert fixture.build(tmp_path / name, name)


def test_fixture_cli_runs(tmp_path):
    assert fixture.main(["--out", str(tmp_path / "cli"), "--world", "hostile"]) == 0
    assert list((tmp_path / "cli").glob("*.pem"))


# --------------------------------------------------------------------------- #
# the guard's own publishing infrastructure
# --------------------------------------------------------------------------- #
def test_ci_badge_does_not_fail_the_prose_lint():
    """A guard that fails the build over its own badge gets switched off."""
    from ananke.collectors.disclosure import scan_text
    badge = ("[![CI](https://github.com/x/y/actions/workflows/ci.yml/badge.svg)]"
             "(https://github.com/x/y/actions/workflows/ci.yml)")
    assert scan_text(badge, strip_code=False) == []


def test_the_forge_is_still_a_host_identifier_in_collected_data():
    """Prose-only. In a record it is a host like any other."""
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"source": "github.com"})


# --------------------------------------------------------------------------- #
# mermaid blocks render only on the forge, so nothing else checks them
# --------------------------------------------------------------------------- #
def test_no_statement_separator_inside_a_mermaid_label():
    """`;` separates statements in mermaid, so one inside a note or a node label
    truncates the statement and the diagram fails to parse.

    This class of defect is invisible to `make verify`: the markdown is valid,
    the lint passes, and the breakage appears only when GitHub renders the page.
    Two shipped in v0.10.0. `classDef` and `class` lines end in `;` legitimately
    and are the only exception.
    """
    import pathlib

    offenders = []
    for name in ("README.md", "docs/ARCHITECTURE.md", "docs/MECHANISMS.md",
                 "docs/METHODOLOGY.md", "docs/THREAT-MODEL.md", "docs/MVP.md"):
        path = pathlib.Path(__file__).resolve().parents[1] / name
        if not path.exists():
            continue
        inside = False
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("```mermaid"):
                inside = True
                continue
            if inside and stripped.startswith("```"):
                inside = False
                continue
            if inside and ";" in stripped and not stripped.startswith(("classDef", "class ")):
                offenders.append(f"{name}:{number}: {stripped}")
    assert offenders == [], "semicolon inside a mermaid statement:\n" + "\n".join(offenders)


# --------------------------------------------------------------------------- #
# sprint 10 review findings: the sector label and the store key
# --------------------------------------------------------------------------- #
def test_sector_label_cannot_carry_a_host_identifier():
    """S1. The sector travels into committed aggregates as a dictionary KEY,
    which the guard's value walk never sees. An operator typing their company
    domain as the sector published the one thing the project promises never to
    publish."""
    from ananke.collectors.sources import LocalPemSource, SectorLabelError

    with pytest.raises(SectorLabelError):
        LocalPemSource("/tmp", "acme-bank.pl production")


def test_sector_label_cannot_carry_markup():
    """S2. Same channel, different payload: markup in the sector was stored XSS
    waiting for the HTML renderer."""
    from ananke.collectors.sources import SectorLabelError, validate_sector

    with pytest.raises(SectorLabelError):
        validate_sector("logistics</script><script>alert(1)</script>")
    with pytest.raises(SectorLabelError):
        validate_sector("x | y |")  # markdown table injection


def test_sector_label_is_shape_validated_not_blocklisted():
    from ananke.collectors.sources import validate_sector

    assert validate_sector("  Energy-Transmission ") == "energy-transmission"
    assert validate_sector("sector_7") == "sector_7"


def test_aggregate_independently_refuses_a_hostile_sector_key(tmp_path, monkeypatch):
    """Defense in depth: even a record written by a source that skipped
    validation must not aggregate under a host-shaped sector."""
    raw = tmp_path / "raw"; raw.mkdir()
    agg = tmp_path / "agg"; agg.mkdir()
    monkeypatch.setattr(passive_cert, "RAW_DIR", raw)
    monkeypatch.setattr(passive_cert, "AGG_DIR", agg)
    passive_cert.HostStore(raw).write("h1", {
        "host": "h1", "sector": "acme-bank.pl", "modality": "first_party_offline",
        "certificates": [{"key_algorithm": "RSA", "key_parameter": 2048,
                          "key_quantum_vulnerable": True,
                          "signature_algorithm": "sha256WithRSA",
                          "valid_beyond_2030_milestone": False,
                          "validity_days": 90}],
    })
    with pytest.raises(DisclosureViolation):
        aggregate(min_bucket=1)


def test_a_san_longer_than_a_filename_does_not_stop_the_run(tmp_path, monkeypatch):
    """S3. A subject CN is capped at 64 bytes by X.509, but a SAN dNSName is
    not, and host identity falls back to SAN. One long name crashed the whole
    collection with OSError before the cap in host_key."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from ananke.collectors.sources import LocalPemSource
    from ananke.collectors.store import host_key

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    long_san = "a" * 250 + ".example"
    pem = (x509.CertificateBuilder().subject_name(x509.Name([]))
           .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
           .public_key(key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now).not_valid_after(now + dt.timedelta(days=90))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(long_san)]),
                          critical=False)
           .sign(key, hashes.SHA256())).public_bytes(serialization.Encoding.PEM)
    (tmp_path / "long.pem").write_bytes(pem)

    raw = tmp_path / "raw"; raw.mkdir()
    monkeypatch.setattr(passive_cert, "RAW_DIR", raw)
    passive_cert.collect(LocalPemSource(tmp_path, "logistics"), ttl=0, force=True)

    assert len(list(raw.rglob("*.json"))) == 1
    assert len(host_key(long_san)) <= 140
    assert host_key(long_san) != host_key("b" + long_san), "cap must keep uniqueness"
