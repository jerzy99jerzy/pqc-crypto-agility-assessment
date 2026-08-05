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

__version__ = "0.10.0"
