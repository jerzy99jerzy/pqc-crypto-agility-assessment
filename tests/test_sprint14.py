"""Sprint 14: the last known hole in the structural guard, and the drift that
let CI run weaker than the local gate.

T14 was found by the threat-model v2.0 review, which re-probed every documented
residual risk instead of re-reading it. Two of the documented holes turned out
to be closed - punycode, credentials in URLs, uppercase hosts and trailing-dot
FQDNs are all caught - and one was real: neither host pattern matches a
colon-separated address, so a bare or bracketed IPv6 literal walked through both
guards.

The implementation is worth reading for the choice it makes. A regex loose
enough to catch every valid IPv6 form also catches clock times, MAC addresses
and C++ scope resolution; one tight enough to avoid those misses compressed
forms. So the pattern only nominates candidates and `ipaddress` decides. That is
exact rather than heuristic: `12:34:56` is rejected because it is not a valid
address, not because a rule was written about what a time looks like.
"""
from __future__ import annotations

import pytest

from ananke.collectors.disclosure import (
    DisclosureViolation,
    assert_no_host_identifiers,
    find_ipv6,
    scan_text,
)


@pytest.mark.parametrize("payload", [
    "2a00:1450:401b:80c::200e",
    "[2a00:1450:401b:80c::200e]:443",
    "2001:db8::1",
    "fe80::1%eth0",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "observed at 2001:db8::dead:beef during collection",
])
def test_ipv6_literals_are_caught_in_both_guards(payload):
    """All of these passed both guards before this sprint."""
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"note": payload})
    assert scan_text(payload, strip_code=False)


@pytest.mark.parametrize("benign", [
    "12:34:56",                    # a time
    "10:30",                       # a time
    "aa:bb:cc:dd:ee:ff",           # a MAC address: six groups, no compression
    "std::vector<int>",            # scope resolution
    "note::see the appendix",
    "key: value",
    "2026-08-05T10:25:53",         # a timestamp
    "make: *** [target] Error 1",  # build output
    "1.1.1.1",                     # IPv4 is the other pattern's job
    "3.5.0",
])
def test_colon_bearing_text_is_not_flagged_as_an_address(benign):
    """The reason validation beats pattern-matching here: none of these needed a
    rule written about it. They are simply not valid addresses."""
    assert find_ipv6(benign) == []


@pytest.mark.parametrize("addr", ["::", "::1"])
def test_addresses_that_identify_nobody_are_exempt(addr):
    """The unspecified address and loopback appear constantly in configuration
    and documentation. Flagging them would train people to disable the guard,
    which is the one outcome worse than a narrow exemption."""
    assert find_ipv6(addr) == []
    assert_no_host_identifiers({"bind": addr})


def test_an_ipv6_address_in_a_zone_form_is_still_an_identifier():
    assert find_ipv6("fe80::1ff:fe23:4567:890a%eth2")


def test_the_guard_reports_which_literal_it_found():
    """A guard that fails without saying what it found gets worked around."""
    with pytest.raises(DisclosureViolation, match="2001:db8"):
        assert_no_host_identifiers({"peer": "2001:db8::5"})


def test_ci_runs_everything_the_local_gate_runs():
    """The Makefile comment said "everything CI runs" while the workflow listed
    checks individually, so two lints added to `verify` were local-only for a
    day. CI now calls `make verify`; this test fails if it goes back to
    restating steps."""
    from pathlib import Path

    workflow = (Path(__file__).resolve().parents[1]
                / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "make verify" in workflow, "CI must call the single gate, not restate it"

    makefile = (Path(__file__).resolve().parents[1] / "Makefile").read_text(encoding="utf-8")
    verify_line = next(line for line in makefile.splitlines() if line.startswith("verify:"))
    for target in ("coverage", "lint-sigma", "lint-spl", "lint-limitations",
                   "lint-disclosure"):
        assert target in verify_line, f"{target} missing from the single gate"
