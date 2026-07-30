"""Test configuration.

Puts the repository root on sys.path once, so tests import the packages whether
or not the project has been `pip install -e .`'d. This replaces the per-file
`sys.path.insert` boilerplate the individual test modules used to carry.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
