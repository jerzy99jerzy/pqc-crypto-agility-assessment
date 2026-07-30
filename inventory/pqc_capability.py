#!/usr/bin/env python3
"""Crypto library PQC capability resolution over a software inventory export.

Closes the open item left by `detection/kql/mde_crypto_library_pqc_capability.kql`,
which degraded to a "verify" bucket because KQL cannot compare semantic versions
safely: `3.10` is not less than `3.5` as a float, and pretending otherwise
misclassifies every host that has already been upgraded.

Input: a CSV export of a software inventory, one row per device and package.
Recognised columns, case-insensitive, first match wins:

    device   : DeviceId, DeviceName, Computer, host, hostname
    name     : SoftwareName, name, package
    vendor   : SoftwareVendor, vendor, publisher
    version  : SoftwareVersion, version

Output: `data/aggregates/pqc_capability.json`, aggregated by library, version
and verdict, with device counts. Device identifiers are consumed for counting
and never written; the disclosure guard runs over the payload before it lands.

Verdicts:
    capable      version >= the configured threshold
    not_capable  version < the threshold
    unknown      no threshold configured, or the version string cannot be parsed

Usage:
    python inventory/pqc_capability.py --inventory export.csv
    python inventory/pqc_capability.py --check openssl 3.4.1
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
from collectors.disclosure import assert_no_host_identifiers  # noqa: E402
from collectors.store import write_json_atomic  # noqa: E402

log = logging.getLogger("pqc_capability")
DEFAULT_CONFIG = REPO_ROOT / "config" / "pqc_capability.yaml"
AGG_DIR = REPO_ROOT / "data" / "aggregates"

COLUMN_ALIASES = {
    "device": ("deviceid", "devicename", "computer", "host", "hostname", "device"),
    "name": ("softwarename", "name", "package", "product"),
    "vendor": ("softwarevendor", "vendor", "publisher"),
    "version": ("softwareversion", "version"),
}

VERSION_RE = re.compile(r"(\d+)|([A-Za-z]+)")


def parse_version(raw: str) -> tuple | None:
    """Parse a version string into a comparable tuple, or None if unusable.

    Handles the shapes that actually appear in inventory exports:
        3.5.0            -> (3, 5, 0)
        3.10.1           -> (3, 10, 1)          compares above 3.5.0, unlike floats
        1.1.1w           -> (1, 1, 1, 'w')      OpenSSL letter releases
        3.5.0-beta1      -> (3, 5, 0, 'beta', 1)
        3.5.0+deb12u2    -> (3, 5, 0, 'deb', 12, 'u', 2)

    Numeric and alphabetic runs are compared within their own type, so a
    numeric component never sorts against a letter. Distribution suffixes
    therefore order after the release they patch, which is the behaviour you
    want when the question is "is this at least 3.5.0".
    """
    if not raw:
        return None
    parts: list = []
    for num, alpha in VERSION_RE.findall(str(raw)):
        parts.append((0, int(num)) if num else (1, alpha.lower()))
    if not parts or parts[0][0] != 0:
        return None  # nothing numeric to anchor on, e.g. "unknown" or "latest"
    return tuple(parts)


def compare_versions(a: str, b: str) -> int | None:
    """Return -1, 0, 1 for a<b, a==b, a>b. None if either side is unparseable."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    # Compare component-wise; a shorter prefix is lower, so 3.5 < 3.5.1
    for x, y in zip(pa, pb):
        if x != y:
            return -1 if x < y else 1
    if len(pa) == len(pb):
        return 0
    return -1 if len(pa) < len(pb) else 1


def load_config(path: Path = DEFAULT_CONFIG) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def match_library(name: str, vendor: str, cfg: dict) -> str | None:
    haystack = f"{name} {vendor}".lower()
    for library, patterns in (cfg.get("name_patterns") or {}).items():
        if any(str(p).lower() in haystack for p in patterns):
            return library
    return None


def resolve(library: str, version: str, cfg: dict) -> dict:
    spec = (cfg.get("libraries") or {}).get(library)
    if spec is None:
        return {"verdict": "unknown", "reason": "library not in configuration"}

    threshold = spec.get("pqc_hybrid_kex_from")
    if threshold is None:
        return {
            "verdict": "unknown",
            "reason": f"no threshold configured ({spec.get('provenance', 'unknown')})",
            "threshold": None,
        }

    cmp = compare_versions(version, str(threshold))
    if cmp is None:
        return {"verdict": "unknown", "reason": f"unparseable version {version!r}",
                "threshold": threshold}
    return {
        "verdict": "capable" if cmp >= 0 else "not_capable",
        "reason": f"{version} {'>=' if cmp >= 0 else '<'} {threshold}",
        "threshold": threshold,
        "provenance": spec.get("provenance", "unknown"),
    }


def _column_map(fieldnames: list[str]) -> dict[str, str]:
    lowered = {f.lower().strip(): f for f in fieldnames or []}
    out: dict[str, str] = {}
    for key, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lowered:
                out[key] = lowered[alias]
                break
    return out


def analyse(inventory: Path, cfg: dict) -> dict:
    rows_total = 0
    rows_matched = 0
    devices: set[str] = set()
    buckets: dict[tuple[str, str, str], dict] = {}
    unmatched_names: Counter = Counter()

    with open(inventory, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        cols = _column_map(reader.fieldnames or [])
        missing = {"name", "version"} - set(cols)
        if missing:
            raise SystemExit(
                f"inventory is missing required column(s): {sorted(missing)}; "
                f"found {reader.fieldnames}"
            )
        for row in reader:
            rows_total += 1
            name = (row.get(cols["name"]) or "").strip()
            vendor = (row.get(cols.get("vendor", "")) or "").strip()
            version = (row.get(cols["version"]) or "").strip()
            device = (row.get(cols.get("device", "")) or "").strip()
            if device:
                devices.add(device)

            library = match_library(name, vendor, cfg)
            if library is None:
                unmatched_names[name.lower()[:40]] += 1
                continue
            rows_matched += 1
            verdict = resolve(library, version, cfg)
            key = (library, version, verdict["verdict"])
            bucket = buckets.setdefault(key, {"rows": 0, "devices": set()})
            bucket["rows"] += 1
            if device:
                bucket["devices"].add(device)

    return _finalise(inventory, cfg, rows_total, rows_matched, devices, buckets,
                     unmatched_names)


def _finalise(inventory, cfg, rows_total, rows_matched, devices, buckets, unmatched):
    findings = []
    for (library, version, verdict), bucket in sorted(buckets.items()):
        detail = resolve(library, version, cfg)
        findings.append({
            "library": library,
            "version": version,
            "verdict": verdict,
            "reason": detail.get("reason"),
            "threshold": detail.get("threshold"),
            "threshold_provenance": detail.get("provenance", "unknown"),
            "rows": bucket["rows"],
            "devices": len(bucket["devices"]),
        })

    summary = Counter(f["verdict"] for f in findings)
    row_summary: Counter = Counter()
    device_summary: Counter = Counter()
    for f in findings:
        row_summary[f["verdict"]] += f["rows"]
        device_summary[f["verdict"]] += f["devices"]

    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_file": Path(inventory).name,
        "config_version": cfg.get("version"),
        "provenance": "measured",
        "interpretation_provenance": "inference",
        "totals": {
            "rows_in_export": rows_total,
            "rows_matched_to_a_crypto_library": rows_matched,
            "distinct_devices_in_export": len(devices),
        },
        "verdict_summary_by_distinct_version": dict(summary),
        "verdict_summary_by_row": dict(row_summary),
        "verdict_summary_by_device_occurrence": dict(device_summary),
        "findings": findings,
        "caveat": (
            "Capability is a precondition, not a measurement of behaviour. A host "
            "running a capable library may still negotiate a classical group "
            "because of policy, middleboxes or a peer that does not offer one. "
            "Pair this with the negotiation rules in detection/sigma/."
        ),
        "unknown_note": (
            "Rows resolved as unknown are not evidence of absence. They are "
            "thresholds nobody has verified yet, and they stay visible rather "
            "than being folded into not_capable."
        ),
    }
    assert_no_host_identifiers(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Resolve PQC capability from a software inventory")
    p.add_argument("--inventory", type=Path, help="CSV export, one row per device and package")
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("--check", nargs=2, metavar=("LIBRARY", "VERSION"),
                   help="resolve a single library/version pair and exit")
    p.add_argument("--out", type=Path, default=AGG_DIR / "pqc_capability.json")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
    cfg = load_config(args.config)

    if args.check:
        library, version = args.check
        print(json.dumps(resolve(library, version, cfg), indent=2))
        return 0

    if not args.inventory:
        p.print_help()
        return 1
    if not args.inventory.exists():
        log.error("inventory not found: %s", args.inventory)
        return 2

    payload = analyse(args.inventory, cfg)
    write_json_atomic(args.out, payload)

    log.info("rows: %d in export, %d matched a crypto library",
             payload["totals"]["rows_in_export"],
             payload["totals"]["rows_matched_to_a_crypto_library"])
    for verdict, n in sorted(payload["verdict_summary_by_row"].items()):
        log.info("  %-12s %d row(s)", verdict, n)
    log.info("written: %s", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
