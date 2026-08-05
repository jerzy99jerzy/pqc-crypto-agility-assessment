"""Handshake parser tests against synthetic transcripts.

These cover the success path of the active probe, which cannot be executed here
because no OpenSSL 3.5 client is available. The subprocess call is not tested;
the parsing of its output is. See tests/fixtures/handshake_transcripts.py for
the provenance disclaimer on the fixtures.
"""

from __future__ import annotations

from ananke.active.handshake_demo import parse_handshake_output  # noqa: E402
from tests.fixtures import handshake_transcripts as fx  # noqa: E402

STARTED = "2026-07-29T00:00:00+00:00"


def _parse(blob: str, rc: int = 0):
    return parse_handshake_output(blob, "ref.example", 443, "X25519MLKEM768", rc, STARTED)


def test_hybrid_single_round_trip():
    r = _parse(fx.HYBRID_SINGLE_RT)
    assert r["negotiated_group"] == "X25519MLKEM768"
    assert r["pqc_hybrid_negotiated"] is True
    assert r["hello_retry_request_inferred"] is False
    assert r["client_hello_count"] == 1
    assert r["protocol"] == "TLSv1.3"
    assert r["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert r["server_temp_key"].startswith("X25519MLKEM768")
    assert "error" not in r


def test_hybrid_with_hello_retry_request():
    r = _parse(fx.HYBRID_WITH_HRR)
    assert r["pqc_hybrid_negotiated"] is True
    assert r["hello_retry_request_inferred"] is True
    assert r["client_hello_count"] == 2


def test_classical_fallback_is_not_flagged_hybrid():
    r = _parse(fx.CLASSICAL_FALLBACK)
    assert r["negotiated_group"] == "X25519"
    assert r["pqc_hybrid_negotiated"] is False
    assert "error" not in r


def test_codepoint_named_hybrid_still_detected():
    """MLKEM appears in the group name even for the SecP256r1 hybrid."""
    r = _parse(fx.HYBRID_CODEPOINT_ONLY)
    assert r["pqc_hybrid_negotiated"] is True


def test_connect_failure_records_error():
    r = _parse(fx.CONNECT_FAILURE, rc=1)
    assert r["negotiated_group"] is None
    assert r["pqc_hybrid_negotiated"] is False
    assert r["error"]


def test_timeout_empty_blob():
    r = _parse(fx.EMPTY_BLOB, rc=-1)
    assert r["negotiated_group"] is None
    assert r["protocol"] is None
    assert r["client_hello_count"] == 0
    assert r["error"]


def test_success_record_has_no_error_field_even_with_zero_group_only():
    """A completed handshake with rc=0 must not carry an error, ever."""
    r = _parse(fx.HYBRID_SINGLE_RT, rc=0)
    assert "error" not in r


def test_parser_is_pure_and_echoes_inputs():
    r = _parse(fx.HYBRID_SINGLE_RT)
    assert r["host"] == "ref.example"
    assert r["offered_groups"] == "X25519MLKEM768"
    assert r["probed_at"] == STARTED
    assert r["provenance"] == "measured"
    assert r["interpretation_provenance"] == "inference"
