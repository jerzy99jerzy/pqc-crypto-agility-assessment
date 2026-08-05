"""Capability resolver tests: version comparison and verdict discipline.

The KQL query this replaces degraded to a "verify" bucket because float
comparison misclassifies 3.10 as older than 3.5. These tests exist mainly to
keep that specific error out.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest
import yaml


from ananke.collectors.disclosure import DisclosureViolation, assert_no_host_identifiers  # noqa: E402
from ananke.inventory.pqc_capability import (  # noqa: E402
    analyse,
    compare_versions,
    load_config,
    match_library,
    parse_version,
    resolve,
)


@pytest.fixture(scope="module")
def cfg():
    return load_config()


@pytest.mark.parametrize("a,b,expected", [
    ("3.5.0", "3.5.0", 0),
    ("3.5.1", "3.5.0", 1),
    ("3.4.9", "3.5.0", -1),
    ("3.10.1", "3.5.0", 1),      # the float-comparison trap
    ("3.9", "3.10", -1),
    # Trailing numeric zeros are insignificant. Inventory exports truncate
    # them, and treating "3.5" as below a "3.5.0" threshold reclassified every
    # truncated-but-upgraded host as not_capable. Regression guard for F2.
    ("3.5", "3.5.0", 0),
    ("3.5.0", "3.5", 0),
    ("3.5.0.0", "3.5", 0),
    ("3.5", "3.5.1", -1),        # a non-zero tail still decides
    ("3.5.1", "3.5", 1),
    ("1.1.1w", "3.5.0", -1),
    ("1.1.1w", "1.1.1a", 1),     # OpenSSL letter releases order lexically
    ("3.5.0-beta1", "3.5.0", 1),
    ("3.5.0+deb12u2", "3.5.0", 1),
])
def test_version_comparison(a, b, expected):
    assert compare_versions(a, b) == expected


def test_truncated_version_resolves_capable(cfg):
    """F2 regression at the verdict level, not just the comparator.

    The threshold is "3.5.0". An export that writes "3.5" describes the same
    release, and must not be reported as not_capable.
    """
    assert resolve("openssl", "3.5", cfg)["verdict"] == "capable"
    assert resolve("openssl", "3.4", cfg)["verdict"] == "not_capable"


@pytest.mark.parametrize("bad", ["", "unknown", "latest", "vendored", None])
def test_unparseable_versions_return_none(bad):
    assert parse_version(bad) is None
    assert compare_versions(bad, "3.5.0") is None


def test_openssl_threshold_verdicts(cfg):
    assert resolve("openssl", "3.5.0", cfg)["verdict"] == "capable"
    assert resolve("openssl", "3.10.1", cfg)["verdict"] == "capable"
    assert resolve("openssl", "3.4.1", cfg)["verdict"] == "not_capable"
    assert resolve("openssl", "1.1.1w", cfg)["verdict"] == "not_capable"


def test_missing_threshold_is_unknown_not_not_capable(cfg):
    """The whole point: an unverified threshold must not be folded into a verdict.

    Reads the config rather than hardcoding which libraries are still null, so
    filling a threshold in a later sprint does not silently break this guard.
    """
    null_libs = [name for name, spec in cfg["libraries"].items()
                 if spec.get("pqc_hybrid_kex_from") is None
                 and spec.get("provenance") != "not_applicable"]
    assert null_libs, "expected at least one unverified library while some remain null"
    for library in null_libs:
        # 99.0.0 is above any plausible sourced-negative ceiling, so a library
        # with pqc_absent_through still lands on unknown here (newer than what
        # was verified) rather than a fabricated verdict.
        result = resolve(library, "99.0.0", cfg)
        assert result["verdict"] == "unknown", library
        # No positive threshold may drive the verdict; a sourced negative
        # reports via absent_through, never via a phantom pqc_hybrid_kex_from.
        assert result.get("threshold") is None


def test_verified_thresholds_produce_real_verdicts(cfg):
    """Libraries with a measured threshold must actually discriminate."""
    verified = [name for name, spec in cfg["libraries"].items()
                if spec.get("pqc_hybrid_kex_from") is not None]
    assert "openssl" in verified and "gnutls" in verified and "wolfssl" in verified
    for library in verified:
        threshold = cfg["libraries"][library]["pqc_hybrid_kex_from"]
        assert resolve(library, threshold, cfg)["verdict"] == "capable"
        assert resolve(library, "0.0.1", cfg)["verdict"] == "not_capable"


def test_boringssl_is_unknown_by_design(cfg):
    assert resolve("boringssl", "chromium-vendored", cfg)["verdict"] == "unknown"


def test_unknown_library_is_unknown(cfg):
    assert resolve("nonexistent-tls", "1.0", cfg)["verdict"] == "unknown"


def test_unparseable_version_of_known_library_is_unknown(cfg):
    r = resolve("openssl", "vendored-snapshot", cfg)
    assert r["verdict"] == "unknown" and "unparseable" in r["reason"]


def test_library_matching_uses_name_and_vendor(cfg):
    assert match_library("libssl3", "Debian", cfg) == "openssl"
    assert match_library("Network Security Services", "Mozilla", cfg) == "nss"
    assert match_library("Microsoft Edge", "Microsoft", cfg) is None


def _write_inventory(path: Path, rows: list[dict], fields: list[str]) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def test_analyse_counts_rows_and_devices(tmp_path: Path, cfg):
    inv = _write_inventory(
        tmp_path / "inv.csv",
        [
            {"DeviceId": "d1", "SoftwareVendor": "openssl", "SoftwareName": "openssl",
             "SoftwareVersion": "3.5.0"},
            {"DeviceId": "d1", "SoftwareVendor": "openssl", "SoftwareName": "libssl3",
             "SoftwareVersion": "3.5.0"},
            {"DeviceId": "d2", "SoftwareVendor": "openssl", "SoftwareName": "openssl",
             "SoftwareVersion": "3.0.13"},
            {"DeviceId": "d3", "SoftwareVendor": "Microsoft", "SoftwareName": "Edge",
             "SoftwareVersion": "126.0"},
        ],
        ["DeviceId", "SoftwareVendor", "SoftwareName", "SoftwareVersion"],
    )
    payload = analyse(inv, cfg)

    assert payload["totals"]["rows_in_export"] == 4
    assert payload["totals"]["rows_matched_to_a_crypto_library"] == 3
    assert payload["totals"]["distinct_devices_in_export"] == 3
    assert payload["verdict_summary_by_row"] == {"capable": 2, "not_capable": 1}
    capable = [f for f in payload["findings"] if f["verdict"] == "capable"][0]
    assert capable["rows"] == 2 and capable["devices"] == 1


def test_analyse_output_carries_no_device_identity(tmp_path: Path, cfg):
    inv = _write_inventory(
        tmp_path / "inv.csv",
        [{"DeviceName": "WKS-FINANCE-01.corp.example", "SoftwareVendor": "openssl",
          "SoftwareName": "openssl", "SoftwareVersion": "3.0.13"}],
        ["DeviceName", "SoftwareVendor", "SoftwareName", "SoftwareVersion"],
    )
    payload = analyse(inv, cfg)
    assert_no_host_identifiers(payload)
    assert "WKS-FINANCE-01" not in json.dumps(payload)


def test_guard_rejects_device_identity_keys():
    for key in ("DeviceId", "DeviceName", "Computer", "hostname"):
        with pytest.raises(DisclosureViolation):
            assert_no_host_identifiers({"findings": [{key: "WKS-001"}]})


def test_alternative_column_names_are_accepted(tmp_path: Path, cfg):
    inv = _write_inventory(
        tmp_path / "inv.csv",
        [{"host": "srv1", "vendor": "openssl", "package": "openssl", "version": "3.5.1"}],
        ["host", "vendor", "package", "version"],
    )
    payload = analyse(inv, cfg)
    assert payload["verdict_summary_by_row"] == {"capable": 1}


def test_missing_required_columns_fails_loudly(tmp_path: Path, cfg):
    inv = _write_inventory(tmp_path / "inv.csv", [{"foo": "bar"}], ["foo"])
    with pytest.raises(SystemExit, match="missing required column"):
        analyse(inv, cfg)


def test_config_thresholds_declare_provenance():
    """A threshold with no provenance label is a guess wearing a number."""
    cfg = load_config()
    for library, spec in cfg["libraries"].items():
        assert "provenance" in spec, library
        if spec["pqc_hybrid_kex_from"] is not None:
            assert spec["provenance"] == "measured", library


def test_every_configured_library_has_name_patterns():
    cfg = load_config()
    assert set(cfg["libraries"]) == set(cfg["name_patterns"])
