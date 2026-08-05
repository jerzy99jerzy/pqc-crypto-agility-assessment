"""The compliance milestone, read from configuration in exactly one place.

Until sprint 11 the date 2030-12-31 was hard-coded in the parser, implied in
the aggregate's counter names, and written into the scoring prose. The date is
correct - it is the EU coordinated roadmap milestone - but a hard-coded
milestone makes the tool a single-regulation instrument, and the report's
central split ("what does normal rotation fix, what needs intervention") is a
function of the milestone, not of the estate.

The value lives in `weights.yaml` under `milestone.date`, next to its
provenance and source, because that is already the file an engagement edits.
Everything else asks here.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import yaml

DEFAULT_MILESTONE = dt.date(2030, 12, 31)
_CONFIG = Path(__file__).resolve().parent / "scoring" / "weights.yaml"


def load_milestone(config: Path | None = None) -> dt.date:
    """Return the configured milestone date, or the EU default.

    Fails soft to the default: a missing or unreadable config must not stop a
    run, because the default is itself a sourced regulatory date, not a guess.
    """
    path = Path(config) if config else _CONFIG
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        value = (raw.get("milestone") or {}).get("date")
    except OSError:
        return DEFAULT_MILESTONE
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return DEFAULT_MILESTONE
    return DEFAULT_MILESTONE
