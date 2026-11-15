"""ANANKE: PQC crypto-agility assessment.

One package rather than five top-level ones. `collectors`, `scoring`,
`inventory`, `active` and `reporting` are names generic enough that installing
this wheel used to plant five collision candidates in site-packages. They live
under `ananke` now, matching the practice in the sibling repositories.

The distribution is still `pqc-crypto-agility-assessment` and the console
scripts are still `pqc-*`: the slug and the commands are what a search engine
and a shell operate on, so they stay descriptive. The import path is a
namespace, and a namespace needs to be unique rather than descriptive.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

# The version is written in one place, pyproject.toml, and read from the
# installed distribution here. Until 0.15.2 this was a literal that still said
# 0.10.0 twelve tagged releases later, and CI's tag check could not see it
# because it compares the tag with pyproject only.
try:
    __version__ = _distribution_version("pqc-crypto-agility-assessment")
except PackageNotFoundError:  # a source tree that was never installed
    __version__ = "0+unknown"
