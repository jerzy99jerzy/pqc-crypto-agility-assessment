"""Sprint 7: capability thresholds for NSS and LibreSSL, verified against
primary sources, plus the resolver mechanism that expresses a sourced negative.

Both libraries were `null -> unknown` before this sprint. Filling them wrong
would be worse than leaving them empty - a wrong threshold silently
reclassifies a whole population - so each value carries a primary source and
the two failure directions are guarded here.

NSS: standardised ML-KEM TLS groups landed in 3.118 (mlkem768x25519 default,
secp256r1mlkem768 / secp384r1mlkem1024 added). The pre-standard Kyber draft was
disabled in 3.116 and 3.117 added no TLS ML-KEM, so 3.118 is a clean cutover.

LibreSSL: a 2025 survey found no PQC in any released version through 3.9. That
is a measured negative, not unknown - and the resolver now distinguishes them.
"""
from __future__ import annotations

import pytest

from inventory.pqc_capability import resolve, load_config


@pytest.fixture(scope="module")
def cfg():
    return load_config()


# --------------------------------------------------------------------------- #
# NSS: 3.118 cutover
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("version,verdict", [
    ("3.108", "not_capable"),   # draft-Kyber era, pre-standard, not counted
    ("3.116", "not_capable"),   # kyber disabled here, standard groups not yet added
    ("3.117", "not_capable"),   # no TLS ML-KEM groups in 3.117
    ("3.118", "capable"),       # standardised groups added + default
    ("3.118.1", "capable"),
    ("3.120", "capable"),
    ("3.124", "capable"),
])
def test_nss_threshold_is_3_118(cfg, version, verdict):
    r = resolve("nss", version, cfg)
    assert r["verdict"] == verdict, r
    assert r["provenance"] == "measured"


def test_nss_truncated_version_resolves(cfg):
    """Depends on the sprint-6 truncation fix: '3.118' must equal '3.118.0'."""
    assert resolve("nss", "3.118", cfg)["verdict"] == "capable"


# --------------------------------------------------------------------------- #
# LibreSSL: sourced negative, not unknown
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("version", ["3.7", "3.8", "3.9", "2.8.0"])
def test_libressl_through_3_9_is_measured_not_capable(cfg, version):
    r = resolve("libressl", version, cfg)
    assert r["verdict"] == "not_capable", r
    assert r["provenance"] == "measured"
    assert "3.9" in r["reason"]


@pytest.mark.parametrize("version", ["3.9.2", "4.0", "4.1.0", "5.0"])
def test_libressl_newer_than_verified_is_unknown_not_overclaimed(cfg, version):
    """The whole point of the sourced-negative mechanism: do NOT assert
    not_capable for a version the source never examined. Newer -> unknown."""
    r = resolve("libressl", version, cfg)
    assert r["verdict"] == "unknown", r
    assert "newer" in r["reason"]


def test_sourced_negative_is_distinct_from_plain_unknown(cfg):
    """A LibreSSL 3.8 (measured not_capable) must not read the same as a
    boringssl row (unknown by design). Conflating them was the defect this
    sprint's resolver change removes."""
    libressl = resolve("libressl", "3.8", cfg)
    boringssl = resolve("boringssl", "1.1.1", cfg)
    assert libressl["verdict"] == "not_capable"
    assert boringssl["verdict"] == "unknown"


def test_unparseable_version_under_absent_through_is_unknown(cfg):
    r = resolve("libressl", "not-a-version", cfg)
    assert r["verdict"] == "unknown"


# --------------------------------------------------------------------------- #
# Resolver precedence: a positive threshold wins over absent_through
# --------------------------------------------------------------------------- #
def test_positive_threshold_takes_precedence_over_absent_through():
    """If a spec ever carried both, the positive cutover is more informative
    and must win. Guards the branch order in resolve()."""
    cfg = {"libraries": {"x": {
        "pqc_hybrid_kex_from": "2.0",
        "pqc_absent_through": "1.0",
        "provenance": "measured",
    }}}
    assert resolve("x", "2.5", cfg)["verdict"] == "capable"
    assert resolve("x", "1.5", cfg)["verdict"] == "not_capable"
