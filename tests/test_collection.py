"""Collection-path tests. No network: the CT client is stubbed or its transport
is monkeypatched.

This closes the largest untested surface left after sprint 2. Until now
`collect_host`, the retry ladder and leaf selection had no coverage, which meant
the only thing verifying the collector was the fact that it imported.
"""

from __future__ import annotations

import datetime as dt
import sys
import urllib.error
from pathlib import Path

import pytest


from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from ananke.collectors import crtsh as crtsh_mod  # noqa: E402
from ananke.collectors.crtsh import CrtShClient, RateLimiter, select_current_leaves  # noqa: E402
from ananke.collectors.sources import CrtShSource  # noqa: E402


def collect_host(client, host, sector, leaves):
    """Sprint 9 moved this onto CrtShSource. The behaviour under test is
    unchanged, so the test keeps its original shape through this adapter."""
    return CrtShSource({}, client, leaves=leaves)._collect_host(host, sector)


def _pem(cn: str, days: int = 90) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class StubClient:
    """Minimal stand-in for CrtShClient. Records calls, raises on demand."""

    def __init__(self, entries, certs=None, search_error=None, fetch_error=None):
        self.entries = entries
        self.certs = certs or {}
        self.search_error = search_error
        self.fetch_error = fetch_error
        self.fetched: list[int] = []

    def search(self, domain, exclude_expired=True):
        if self.search_error:
            raise self.search_error
        return self.entries

    def fetch_certificate(self, crtsh_id):
        self.fetched.append(crtsh_id)
        if self.fetch_error:
            raise self.fetch_error
        return self.certs.get(crtsh_id, _pem("stub.test"))


# --- leaf selection ---------------------------------------------------------

def test_select_current_leaves_dedupes_by_serial_and_sorts_by_recency():
    entries = [
        {"id": 1, "serial_number": "aa", "entry_timestamp": "2026-01-01T00:00:00"},
        {"id": 2, "serial_number": "aa", "entry_timestamp": "2026-06-01T00:00:00"},
        {"id": 3, "serial_number": "bb", "entry_timestamp": "2026-05-01T00:00:00"},
        {"id": 4, "serial_number": "cc", "entry_timestamp": "2026-04-01T00:00:00"},
    ]
    picked = select_current_leaves(entries, limit=2)
    assert [e["id"] for e in picked] == [2, 3]


def test_select_current_leaves_tolerates_missing_timestamps():
    entries = [{"id": 1, "serial_number": "aa"}, {"id": 2, "serial_number": "bb"}]
    assert len(select_current_leaves(entries, limit=5)) == 2


# --- collect_host -----------------------------------------------------------

def test_collect_host_parses_dimensions_and_tags_modality():
    entries = [{"id": 7, "serial_number": "aa", "entry_timestamp": "2026-07-01T00:00:00"}]
    client = StubClient(entries, certs={7: _pem("h1.finance.test", days=397)})

    rec = collect_host(client, "h1.finance.test", "finance", leaves=2)

    assert rec["modality"] == "passive"
    assert rec["source"] == "crt.sh"
    assert rec["errors"] == []
    assert len(rec["certificates"]) == 1
    cert = rec["certificates"][0]
    assert cert["key_algorithm"] == "RSA"
    assert cert["key_quantum_vulnerable"] is True
    assert cert["validity_days"] == 397
    assert cert["crtsh_id"] == 7
    assert cert["ct_entry_timestamp"] == "2026-07-01T00:00:00"


def test_collect_host_records_search_failure_without_raising():
    client = StubClient([], search_error=RuntimeError("crt.sh unreachable"))
    rec = collect_host(client, "h1.test", "finance", leaves=2)
    assert rec["certificates"] == []
    assert rec["errors"] and "search" in rec["errors"][0]


def test_collect_host_survives_one_bad_fetch():
    entries = [
        {"id": 1, "serial_number": "aa", "entry_timestamp": "2026-07-02T00:00:00"},
        {"id": 2, "serial_number": "bb", "entry_timestamp": "2026-07-01T00:00:00"},
    ]
    client = StubClient(entries, fetch_error=OSError("connection reset"))
    rec = collect_host(client, "h1.test", "finance", leaves=2)
    assert rec["certificates"] == []
    assert len(rec["errors"]) == 2  # one per attempted leaf, batch not aborted


def test_collect_host_skips_entries_without_id():
    entries = [{"serial_number": "aa", "entry_timestamp": "2026-07-01T00:00:00"}]
    client = StubClient(entries)
    rec = collect_host(client, "h1.test", "finance", leaves=2)
    assert rec["certificates"] == [] and client.fetched == []


def test_unparseable_certificate_is_recorded_not_dropped():
    entries = [{"id": 9, "serial_number": "aa", "entry_timestamp": "2026-07-01T00:00:00"}]
    client = StubClient(entries, certs={9: b"<html>rate limited</html>"})
    rec = collect_host(client, "h1.test", "finance", leaves=1)
    assert len(rec["certificates"]) == 1
    assert rec["certificates"][0]["parse_error"]
    # aggregation filters these out, so a rate-limit page cannot masquerade as
    # a host with no vulnerable key
    assert rec["certificates"][0]["key_algorithm"] is None


# --- transport: retry ladder and limiter ------------------------------------

class FakeResponse:
    def __init__(self, body: bytes):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_client_retries_on_502_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.HTTPError(req.full_url, 502, "Bad Gateway", {}, None)
        return FakeResponse(b'[{"id": 1}]')

    monkeypatch.setattr(crtsh_mod.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(crtsh_mod.time, "sleep", lambda *_: None)

    client = CrtShClient(rate=RateLimiter(min_interval=0.0, jitter=0.0))
    assert client.search("example.com") == [{"id": 1}]
    assert calls["n"] == 3


def test_client_does_not_retry_on_404(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(crtsh_mod.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(crtsh_mod.time, "sleep", lambda *_: None)

    client = CrtShClient(rate=RateLimiter(min_interval=0.0, jitter=0.0))
    with pytest.raises(urllib.error.HTTPError):
        client.search("example.com")
    assert calls["n"] == 1


def test_client_gives_up_after_max_retries(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(crtsh_mod.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(crtsh_mod.time, "sleep", lambda *_: None)

    client = CrtShClient(rate=RateLimiter(min_interval=0.0, jitter=0.0), max_retries=2)
    with pytest.raises(RuntimeError, match="unreachable after 2 attempts"):
        client.search("example.com")


def test_empty_and_non_json_responses_are_not_fatal(monkeypatch):
    bodies = [b"   ", b"<html>502</html>"]

    def fake_urlopen(req, timeout=None):
        return FakeResponse(bodies.pop(0))

    monkeypatch.setattr(crtsh_mod.urllib.request, "urlopen", fake_urlopen)
    client = CrtShClient(rate=RateLimiter(min_interval=0.0, jitter=0.0))
    assert client.search("example.com") == []
    assert client.search("example.com") == []


def test_rate_limiter_enforces_minimum_interval(monkeypatch):
    slept: list[float] = []
    clock = {"t": 0.0}
    monkeypatch.setattr(crtsh_mod.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(crtsh_mod.time, "sleep", lambda s: slept.append(s))

    limiter = RateLimiter(min_interval=2.0, jitter=0.0)
    limiter.wait()          # first call, no wait
    clock["t"] = 0.5
    limiter.wait()          # 0.5s elapsed, must sleep the remaining 1.5s
    assert slept == [1.5]


def test_rate_limiter_does_not_sleep_before_the_first_request(monkeypatch):
    """Regression: _last defaulted to 0.0, so a small monotonic() epoch caused a
    full-interval sleep before the very first call."""
    slept: list[float] = []
    monkeypatch.setattr(crtsh_mod.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(crtsh_mod.time, "sleep", lambda s: slept.append(s))
    RateLimiter(min_interval=2.0, jitter=0.0).wait()
    assert slept == []
