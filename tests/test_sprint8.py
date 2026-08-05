"""Sprint 8: the disclosure guard's boundary defect, and the end of the
hand-maintained filename allowlist.

Two things are tested here, and only the first is a bug.

D1. `HOSTNAME_RE` and `IPV4_RE` were anchored on `\\b`. `_` is a word
character, so no boundary exists between `_` and a letter, and a match may
only begin at a boundary: `acme_bank.pl` and `host_10.0.0.1` produced no
match at all and passed the strict guard silently. That is a false negative in
the one module that enforces the project's scope statement, and every case
below fails against the previous release.

D2. The filename allowlist was hand-maintained, so every new repo file with a
live-ccTLD extension (`.md` is Moldova) turned CI red until someone appended
another literal. Filenames are now derived from the tracked file list. The
security-relevant property is that the derivation is admitted in the prose
scan only - the strict guard, which is what structured collected data passes
through, keeps zero filename exemptions.
"""
from __future__ import annotations

import subprocess

import pytest

from ananke.collectors.disclosure import (
    ALLOWED_TOKENS,
    HOSTNAME_RE,
    DisclosureViolation,
    _repo_file_tokens,
    assert_no_host_identifiers,
    scan_text,
)


# --------------------------------------------------------------------------- #
# D1: host identity glued to a delimiter that is not a word boundary
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("payload", [
    "acme_bank.pl",
    "cn=corp_bank.pl",
    "seen at mail_pkobp.pl today",
    "prefix_example.com",
    "bank.pl_backup",
])
def test_underscore_adjacent_hostname_is_caught(payload):
    """Pre-sprint-8 these produced no regex match and passed the guard."""
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"note": payload})
    assert scan_text(payload), "prose scan must see it too"


@pytest.mark.parametrize("payload", [
    "host_10.0.0.1",
    "sensor_192.168.1.10 reported",
])
def test_underscore_adjacent_ipv4_is_caught(payload):
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"note": payload})


@pytest.mark.parametrize("benign", [
    "3.5.0",
    "3.5.0.2024",       # four-part version, last component out of octet range
    "openssl 3.0.13",
    "1.1.1w",
])
def test_version_strings_are_not_flagged(benign):
    """The looser boundary must not start matching on a shifted window."""
    assert_no_host_identifiers({"version": benign})


def test_dotted_run_is_not_matched_piecewise():
    """A longer name yields one full match, not a suffix match as well."""
    assert HOSTNAME_RE.findall("a.bank.pl") == ["a.bank.pl"]


# --------------------------------------------------------------------------- #
# D2: derived filename allowlist, and the strict/prose split
# --------------------------------------------------------------------------- #
def test_prose_scan_accepts_tracked_repo_filenames():
    """The case that turned main red in CI #9, plus the tokens the regex
    actually extracts from underscored filenames."""
    text = "See LICENSING.md, docs/mechanisms.md and hndl_score.py for detail."
    assert scan_text(text, strip_code=False) == []


def test_strict_guard_keeps_zero_filename_exemptions():
    """The derived allowlist must not reach structured output. `.md` is a live
    ccTLD; collected data lands here."""
    with pytest.raises(DisclosureViolation):
        assert_no_host_identifiers({"source": "mechanisms.md"})


def test_no_dead_entries_in_allowed_tokens():
    """An entry HOSTNAME_RE never yields is dead weight that reads as coverage.

    Eight of twenty-four entries were unreachable before this sprint - every
    one containing an underscore, because the regex tokenises `hndl_score.py`
    as `score.py`. Appending a literal that can never match is how an allowlist
    rots quietly.
    """
    dead = sorted(t for t in ALLOWED_TOKENS if t not in HOSTNAME_RE.findall(t))
    assert dead == [], f"unreachable ALLOWED_TOKENS entries: {dead}"


def test_derived_tokens_include_extracted_subtoken():
    tokens = _repo_file_tokens()
    assert "score.py" in tokens, "regex yields score.py from hndl_score.py"
    assert "mechanisms.md" in tokens


def test_derivation_prefers_git_and_filters_extensions(tmp_path):
    """git ls-files is authoritative: a tracked file counts, an untracked one
    in the same directory does not, and a ccTLD-shaped name outside the
    permitted extensions is never admitted."""
    if not _git_available():
        pytest.skip("git not present in this environment")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "handbook.md").write_text("x", encoding="utf-8")
    (tmp_path / "untracked.md").write_text("x", encoding="utf-8")
    (tmp_path / "victim.pl").write_text("x", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "handbook.md", "victim.pl"],
                   check=True)

    tokens = _repo_file_tokens(str(tmp_path))
    assert "handbook.md" in tokens
    assert "untracked.md" not in tokens, "not tracked, must not be allowlisted"
    assert "victim.pl" not in tokens, ".pl is a ccTLD, not a permitted extension"


def _fake_checkout(root):
    """Marker files the fallback requires before it will walk a directory."""
    (root / "pyproject.toml").write_text("x", encoding="utf-8")
    (root / "ananke").mkdir(exist_ok=True)


def test_walk_fallback_never_allowlists_the_raw_store(tmp_path):
    """No git here, so the filesystem fallback runs. A filename under data/ can
    be host-derived; it must not be able to whitelist itself."""
    _fake_checkout(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "handbook.md").write_text("x", encoding="utf-8")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "targetbank.md").write_text("x", encoding="utf-8")

    tokens = _repo_file_tokens(str(tmp_path))
    assert "handbook.md" in tokens
    assert "targetbank.md" not in tokens


def test_walk_fallback_refuses_a_directory_that_is_not_this_repo(tmp_path):
    """`_REPO_ROOT` resolves to site-packages for an installed wheel. Walking
    it would allowlist filenames from unrelated packages."""
    (tmp_path / "somepkg").mkdir()
    (tmp_path / "somepkg" / "handbook.md").write_text("x", encoding="utf-8")
    assert _repo_file_tokens(str(tmp_path)) == frozenset()


def test_derivation_fails_closed_on_a_missing_root(tmp_path):
    """No allowlist is safer than a wrong one."""
    assert _repo_file_tokens(str(tmp_path / "does-not-exist")) == frozenset()


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
