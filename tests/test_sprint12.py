"""Sprint 12: the only available control on the client who supplies a
convenient dump, and a second detection target.

The cross-check exists because of adversary A3 in `docs/THREAT-MODEL.md`.
Nothing inside a directory of certificates can show that the directory is the
estate, so completeness stays `reported` no matter how carefully each file is
parsed. What can be done is to look for the same operator in a record they do
not curate, which is what Certificate Transparency is.

The asymmetry carries the design and most of these tests. Present in CT and
absent from the dump is a finding. Present in the dump and absent from CT is
not: internal PKI issues certificates that never reach a public log, and
counting that as a discrepancy would produce noise in direct proportion to how
well the operator runs their internal CA. Getting this backwards would make the
check actively misleading, so it is pinned from both directions.

The second property is that the output is counts. The comparison needs host
names, does the comparison in memory, and writes a number. A report that
travels must not carry the list of undeclared hosts, because that list is
exactly the artefact this project promises never to publish.
"""
from __future__ import annotations

import json

import pytest

from ananke.collectors.crosscheck import compare, normalise, run
from ananke.collectors.disclosure import DisclosureViolation, assert_no_host_identifiers


def _store(path, hosts):
    path.mkdir(parents=True, exist_ok=True)
    for host in hosts:
        rec = {"host": host, "sector": "logistics",
               "modality": "first_party_offline", "certificates": []}
        safe = host.replace("*", "_").replace(".", "_")
        (path / f"{safe}.json").write_text(json.dumps(rec), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# the asymmetry
# --------------------------------------------------------------------------- #
def test_publicly_logged_but_undeclared_is_the_finding():
    result = compare(reported={"gw.op.example"},
                     public={"gw.op.example", "forgotten-vpn.op.example"})
    assert result["publicly_logged_not_in_reported_set"] == 1
    assert result["in_both"] == 1


def test_declared_but_not_publicly_logged_is_not_a_finding():
    """An internal PKI legitimately never reaches a public log. Counting this
    as a gap would generate noise proportional to how well the CA is run."""
    result = compare(reported={"gw.op.example", "internal-erp.op.example"},
                     public={"gw.op.example"})
    assert result["publicly_logged_not_in_reported_set"] == 0
    assert result["reported_not_publicly_logged"] == 1
    assert "not evidence of anything" in result["interpretation"]["not_a_gap"]


def test_the_blind_spot_is_stated_rather_than_implied():
    """A host with an internally issued certificate that was also omitted is
    invisible to both sides. The check narrows the gap; it does not close it."""
    result = compare(reported=set(), public=set())
    assert "does not close it" in result["interpretation"]["blind_spot"]


def test_coverage_is_none_rather_than_zero_when_nothing_is_public():
    """No public footprint means the check could not run, which is not the same
    as a coverage of zero."""
    assert compare({"a.example"}, set())["public_coverage_of_reported_set"] is None


# --------------------------------------------------------------------------- #
# comparison hygiene
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    ("*.shop.op.example", "shop.op.example"),
    ("GW.OP.EXAMPLE", "gw.op.example"),
    ("api.op.example.", "api.op.example"),
    ("  edge.op.example  ", "edge.op.example"),
])
def test_normalisation_prevents_false_discrepancies(raw, expected):
    """A wildcard covers the apex, a trailing dot is the same name, and case is
    not identity. Each of these would otherwise register as a missing host."""
    assert normalise(raw) == expected


def test_wildcard_in_ct_matches_the_declared_apex():
    result = compare(reported={"shop.op.example"}, public={"*.shop.op.example"})
    assert result["publicly_logged_not_in_reported_set"] == 0


def test_unidentified_placeholders_are_excluded(tmp_path):
    """`unidentified-<stem>` is a placeholder from a certificate with no usable
    subject, not a host, and must not count as a declared one."""
    reported = _store(tmp_path / "dump", ["gw.op.example", "unidentified-mystery"])
    public = _store(tmp_path / "ct", ["gw.op.example"])
    payload = run(reported, public, tmp_path / "out.json")
    assert payload["result"]["reported_hosts"] == 1


# --------------------------------------------------------------------------- #
# counts only
# --------------------------------------------------------------------------- #
def test_no_host_name_reaches_the_written_result(tmp_path):
    reported = _store(tmp_path / "dump", ["gw.op.example"])
    public = _store(tmp_path / "ct",
                    ["gw.op.example", "forgotten-vpn.op.example", "legacy.op.example"])
    out = tmp_path / "estate_completeness.json"
    payload = run(reported, public, out)

    blob = out.read_text(encoding="utf-8")
    for name in ("gw.op.example", "forgotten-vpn", "legacy.op.example"):
        assert name not in blob
    assert payload["result"]["publicly_logged_not_in_reported_set"] == 2
    assert_no_host_identifiers(payload)


def test_written_result_passes_the_guard_even_though_it_is_counts(tmp_path):
    """Every path into the committed aggregates directory is gated, including
    the ones that should be safe by construction."""
    reported = _store(tmp_path / "dump", ["a.op.example"])
    public = _store(tmp_path / "ct", ["a.op.example"])
    payload = run(reported, public, tmp_path / "o.json")
    assert_no_host_identifiers(payload)
    assert payload["disclosure_policy"]["granularity"] == "counts"


def test_a_hostile_host_value_cannot_ride_into_the_output(tmp_path):
    """Defense in depth: even if a store record carried something host-shaped
    into a place counts are expected, the guard on write catches it."""
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"result": {"note": "missing gw.acme-bank.pl"}})


# --------------------------------------------------------------------------- #
# SPL pack discipline
# --------------------------------------------------------------------------- #
def test_every_spl_search_declares_its_validation_status():
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / "tests" / "validate_spl.py")],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_spl_lint_catches_a_dropped_unknown_state(tmp_path, monkeypatch):
    """The tri-state rule is the one that matters: a filter written as
    `="true"` reports an unrecognised algorithm as safe."""
    import tests.validate_spl as lint

    bad = tmp_path / "bad.spl"
    bad.write_text(
        "* Question: x\n* Source: y\n* Validation status: [inference]\n"
        'index=z | where quantum_vulnerable="true"\n', encoding="utf-8")
    problems = lint.check(bad)
    assert any("unknown" in p for p in problems)


def test_spl_lint_ignores_the_anti_pattern_when_it_appears_in_a_comment(tmp_path):
    """Found by running the lint against this repository's own pack: scanning
    the whole file flagged the comment that warns against the anti-pattern,
    which is how a linter teaches people to stop documenting it."""
    import tests.validate_spl as lint

    good = tmp_path / "good.spl"
    good.write_text(
        "* Question: x\n* Source: y\n* Validation status: [inference]\n"
        '* A filter written as quantum_vulnerable="true" would drop unknown.\n'
        'index=z | where quantum_vulnerable!="false"\n', encoding="utf-8")
    assert lint.check(good) == []
