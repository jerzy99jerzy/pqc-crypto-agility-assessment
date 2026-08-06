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
