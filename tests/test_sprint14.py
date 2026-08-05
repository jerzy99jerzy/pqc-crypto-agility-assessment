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


def test_the_repository_map_is_checked_by_the_gate():
    """The map went stale for four sprints after the namespace refactor and was
    caught by a reader. The instance is fixed in the README; this asserts the
    class is closed, which is the part that matters."""
    from pathlib import Path

    makefile = (Path(__file__).resolve().parents[1] / "Makefile").read_text(encoding="utf-8")
    verify_line = next(line for line in makefile.splitlines() if line.startswith("verify:"))
    assert "lint-layout" in verify_line


def test_layout_lint_catches_drift_in_both_directions(tmp_path, monkeypatch):
    """A path drawn but absent, and a path present but undrawn. Either alone
    would let half the class through."""
    import tests.lint_layout as lint

    monkeypatch.setattr(lint, "ROOT", tmp_path)
    monkeypatch.setattr(lint, "README", tmp_path / "README.md")
    (tmp_path / "ananke").mkdir()
    (tmp_path / "ananke" / "real.py").write_text("", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "```\npqc-crypto-agility-assessment/\n"
        "├── ananke/\n│   └── imaginary.py\n```\n", encoding="utf-8")

    mapped = lint._mapped_names()
    expected = lint._expected_names()
    assert "imaginary.py" in mapped and "imaginary.py" not in expected
    assert "real.py" in expected and "real.py" not in mapped


def test_the_lint_target_can_actually_fail():
    """`A && B || C` returns C's status, so a real ruff error printed "SKIP" and
    the gate went green. The lint target was incapable of failing, in the target
    that exists to prevent things passing silently. Fixed with if/then/else;
    this asserts the shape rather than the behaviour, because invoking make from
    a test is slower and less specific than reading the recipe."""
    from pathlib import Path

    makefile = (Path(__file__).resolve().parents[1] / "Makefile").read_text(encoding="utf-8")
    recipe = makefile.split("lint:", 1)[1].split("\nlint-sigma:", 1)[0]
    assert "&& ruff check . ||" not in recipe, (
        "the `A && B || C` form swallows a real failure; use if/then/else")
    assert "if command -v ruff" in recipe


def test_layout_check_tolerates_generated_artefacts():
    """A clean checkout has no `docs/report.md` until something generates it.
    The map should still draw it, so its absence must not be called drift."""
    import tests.lint_layout as lint

    assert "report.md" in lint.GENERATED
    assert "sectors.json" in lint.GENERATED


def test_layout_check_survives_a_clean_checkout(tmp_path_factory, monkeypatch):
    """Failed in CI twice, and both times the fix was another literal. A clean
    checkout has no `data/raw/` (git-ignored) and no generated report, and the
    map is right to draw both: a reader needs to know where output lands.

    The exemption is derived from `.gitignore` rather than enumerated, which is
    the same answer sprint 8 gave the hand-maintained disclosure allowlist. The
    short explicit list beside it covers output whose tracking status differs
    between clones, and the two mechanisms are kept separate so it stays clear
    which one is doing the work.
    """
    import subprocess

    import tests.lint_layout as lint

    if not _git_available():
        pytest.skip("git not present in this environment")

    # A synthetic repository rather than the real one: the assertion is about
    # the matching rule, and a test that depends on the surrounding checkout
    # having a .git directory is the same environmental assumption this whole
    # class of defect is made of.
    repo = tmp_path_factory.mktemp("repo")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / ".gitignore").write_text("data/raw/\n", encoding="utf-8")
    monkeypatch.setattr(lint, "ROOT", repo)

    assert lint._git_ignores("raw"), (
        "a directory pattern needs the trailing-slash form once the directory "
        "is gone, which is exactly the clean-checkout case")
    assert not lint._git_ignores("sources.py")
    assert "report.md" in lint.GENERATED


def test_layout_check_still_fails_on_real_drift(tmp_path, monkeypatch):
    """The exemptions must not swallow the case the check exists for."""
    import tests.lint_layout as lint

    monkeypatch.setattr(lint, "ROOT", tmp_path)
    monkeypatch.setattr(lint, "README", tmp_path / "README.md")
    (tmp_path / "ananke").mkdir()
    (tmp_path / "README.md").write_text(
        "```\npqc-crypto-agility-assessment/\n"
        "├── ananke/\n│   └── vanished.py\n```\n", encoding="utf-8")

    assert "vanished.py" in lint._mapped_names()
    assert not lint._git_ignores("vanished.py")


def _git_available() -> bool:
    import subprocess
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
