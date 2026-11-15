"""Sprint 15: the layout check's gitignore exemption, applied both ways."""
import subprocess

import pytest


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def test_ignored_output_directory_is_not_expected_in_the_map(tmp_path, monkeypatch):
    """A git-ignored directory that exists on disk must not fail the layout
    check.

    v0.14.3 derived the exemption from gitignore for paths the map draws but
    the tree lacks, and left the opposite direction reading a hand-written
    SKIP_PARTS. `runs/`, added for run logs, was ignored by git, absent from
    SKIP_PARTS, and broke `make verify` on the first real run. The rule now
    reads the same way in both directions: if the repository ignores a path,
    the map is not expected to draw it.
    """
    import tests.lint_layout as lint

    if not _git_available():
        pytest.skip("git not present in this environment")

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True,
                   capture_output=True)
    (tmp_path / ".gitignore").write_text("runs/\n", encoding="utf-8")
    (tmp_path / "ananke").mkdir()
    (tmp_path / "ananke" / "real.py").write_text("", encoding="utf-8")
    (tmp_path / "runs" / "20260806-1010").mkdir(parents=True)
    (tmp_path / "runs" / "20260806-1010" / "collect.log").write_text(
        "", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "```\npqc-crypto-agility-assessment/\n"
        "├── ananke/\n│   └── real.py\n```\n", encoding="utf-8")

    monkeypatch.setattr(lint, "ROOT", tmp_path)
    monkeypatch.setattr(lint, "README", tmp_path / "README.md")

    expected = lint._expected_names()
    assert "runs" not in expected
    assert "20260806-1010" not in expected
    assert "real.py" in expected


# --------------------------------------------------------------------------- #
# 0.15.2: the package's description of itself, in the places a reader meets it
# --------------------------------------------------------------------------- #
def _sectors(first_party: bool) -> dict:
    return {
        "generated_at": "2026-11-15T00:00:00+00:00",
        "modality": "D_first_party_offline" if first_party else "A_passive_public_ct",
        "provenance": "reported" if first_party else "measured",
        "milestone": {"date": "2030-12-31"},
        "disclosure_policy": {"first_party_estate": first_party},
        "sectors": {"logistics": {
            "hosts_observed": 5, "hosts_with_certificate": 5,
            "self_resolving_via_rotation": 3, "intervention_required": 2,
            "rotation_bands": {"<=100d": 3, ">1100d": 2},
            "rotation_stats": {"median": 90, "min": 47, "max": 1200,
                               "rotations_before_milestone": 16.0},
            "valid_beyond_milestone": {"True": 2, "False": 3},
            "issuers": {"Example Trust Services": 5},
        }},
    }


def test_package_version_is_the_distribution_version():
    """`ananke.__version__` still said 0.10.0 in the twelve tagged releases after
    0.10.0. It is now read from the installed distribution, so pyproject.toml is
    the only place the version is written."""
    from importlib.metadata import version

    import ananke

    assert ananke.__version__ == version("pqc-crypto-agility-assessment")


def test_markdown_report_prints_the_shared_limitations_only():
    """The markdown report kept "Cryptography at rest." and "HSMs." in 0.13.0,
    which found the flat at-rest claim false, and in the seven tagged releases
    after it. It now prints the shared list, and the retired lines are gone."""
    from ananke.reporting.build_report import build
    from ananke.reporting.limitations import LIMITATIONS

    text = build()
    for _, sentence in LIMITATIONS:
        assert f"- {sentence}" in text
    assert "- Cryptography at rest.\n" not in text
    assert "- HSMs.\n" not in text


def test_html_report_prints_the_shared_limitations():
    from ananke.reporting.html_report import esc, render_html
    from ananke.reporting.limitations import LIMITATIONS

    out = render_html(_sectors(first_party=False), None, [])
    for _, sentence in LIMITATIONS:
        assert esc(sentence) in out
    assert "Cryptography at rest, HSMs" not in out


def test_html_header_states_the_chart_read_when_there_is_one():
    """The header said "host-level data was not read by this renderer" while
    the first-party chart embedded date pairs taken from the raw store."""
    from ananke.reporting.html_report import render_html

    pairs = [{"nb": "2026-01-01", "na": "2026-04-01"}]
    with_chart = render_html(_sectors(first_party=True), None, pairs)
    assert 'id="horizon"' in with_chart
    assert "plus certificate validity dates" in with_chart
    assert "not read for this report" not in with_chart

    third_party = render_html(_sectors(first_party=False), None, pairs)
    assert 'id="horizon"' not in third_party
    assert "not read for this report" in third_party


def test_limitations_lint_fails_when_report_list_and_registry_disagree():
    """Bidirectional, like the README check: a registered claim missing from
    the report list fails, and so does a report entry nothing registers."""
    import tests.lint_limitations as lint
    from ananke.reporting.limitations import LIMITATIONS

    assert lint.report_list_failures(LIMITATIONS) == []
    assert lint.report_list_failures(LIMITATIONS[1:]), "a missing entry must fail"
    extra = LIMITATIONS + (("Nothing registers this claim", "Unchecked."),)
    assert lint.report_list_failures(extra), "an unregistered entry must fail"
