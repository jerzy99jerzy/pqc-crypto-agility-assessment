#!/usr/bin/env python3
"""Target selection from a public ranking, with the selection recorded.

A percentage without a stated denominator is decoration. This module produces
two artefacts from one run:

    config/targets.yaml            the working target list  [git-ignored]
    data/aggregates/
        selection_manifest.json    what was selected and how [committed]

The manifest carries the input file name, its SHA-256, the filters applied, the
classification rules that were in force, and per-sector counts. It carries no
domain names, so it can be committed and cited without publishing a target
list. A reader can therefore challenge the sampling without being handed the
sample.

Input: a Tranco-style CSV, `rank,domain`, one row per line. Downloading it is
deliberately not automated - the list is versioned and dated upstream, and
pinning a specific file by hash is the whole point.

Usage:
    python collectors/select_targets.py --ranking tranco_XXXX.csv --suffix .pl --top 5000
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import logging
import sys
from collections import Counter
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from ananke.collectors.disclosure import assert_no_host_identifiers  # noqa: E402
from ananke.collectors.store import write_json_atomic  # noqa: E402

log = logging.getLogger("select_targets")
DEFAULT_RULES = REPO_ROOT / "config" / "classification.yaml"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_rules(path: Path) -> dict:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return doc.get("rules") or {}


def matching_rules(domain: str, rules: dict) -> list[tuple[str, str]]:
    """Return every (sector, rule) that matches, not just the winner.

    Substring matching on concatenated domain labels collides in ways that are
    invisible until counted. The Polish token `gaz` matches `gazeta`, so a
    newspaper lands in the energy sector and nobody notices, because first match
    wins and the loser leaves no trace. Collecting all matches makes the
    ambiguity countable, and the count goes into the manifest.
    """
    d = domain.lower()
    hits: list[tuple[str, str]] = []
    for sector, spec in rules.items():
        if any(str(x).lower() in d for x in (spec.get("exclude") or [])):
            continue
        for exact in spec.get("exact") or []:
            if d == str(exact).lower():
                hits.append((sector, f"{sector}.exact:{exact}"))
        for token in spec.get("contains") or []:
            if str(token).lower() in d:
                hits.append((sector, f"{sector}.contains:{token}"))
        for suffix in spec.get("suffix") or []:
            if d.endswith(str(suffix).lower()):
                hits.append((sector, f"{sector}.suffix:{suffix}"))
    return hits


def classify(domain: str, rules: dict) -> tuple[str, str]:
    """Return (sector, rule_that_matched).

    First match wins, and the winning rule is recorded, so a disputed
    classification can be traced to the line that caused it rather than to a
    judgement call nobody wrote down. Rule order in the config is therefore
    load bearing; collisions are reported separately by the manifest.
    """
    hits = matching_rules(domain, rules)
    return hits[0] if hits else ("unclassified", "none")


def read_ranking(path: Path, suffix: str | None, top: int | None) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) < 2:
                continue
            try:
                rank = int(row[0])
            except ValueError:
                continue  # header line
            domain = row[1].strip().lower()
            if top is not None and rank > top:
                continue
            if suffix and not domain.endswith(suffix.lower()):
                continue
            rows.append((rank, domain))
    return rows


def select(ranking: Path, rules_path: Path, suffix: str | None, top: int | None,
           min_bucket: int) -> tuple[dict[str, list[str]], dict]:
    rules = load_rules(rules_path)
    rows = read_ranking(ranking, suffix, top)

    sectors: dict[str, list[str]] = {}
    rule_hits: Counter[str] = Counter()
    collisions: Counter[str] = Counter()
    ambiguous = 0
    for _rank, domain in rows:
        hits = matching_rules(domain, rules)
        distinct_sectors = {s for s, _ in hits}
        if len(distinct_sectors) > 1:
            ambiguous += 1
            collisions[" | ".join(sorted({r for _, r in hits}))] += 1
        sector, rule = (hits[0] if hits else ("unclassified", "none"))
        rule_hits[rule] += 1
        if sector == "unclassified":
            continue
        sectors.setdefault(sector, []).append(domain)

    counts = {s: len(v) for s, v in sectors.items()}
    undersized = sorted(s for s, n in counts.items() if n < min_bucket)

    manifest = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "provenance": "measured",
        "source": {
            "file_name": ranking.name,
            "file_sha256": sha256_file(ranking),
            "rows_in_scope": len(rows),
        },
        "filters": {"suffix": suffix, "top_rank": top},
        "classification": {
            "rules_file": rules_path.name,
            "rules_sha256": sha256_file(rules_path),
            "rule_hits": dict(rule_hits),
            "unclassified": rule_hits.get("none", 0),
            "ambiguous_domains": ambiguous,
            "rule_collisions": dict(collisions),
            "ambiguity_note": (
                "Domains matched by rules from more than one sector. Resolved by "
                "config order, first match wins. Counted here rather than resolved "
                "silently: a collision is a defect in the ruleset, and a ruleset "
                "that hides its collisions produces a denominator nobody can audit."
            ),
        },
        "sector_counts": counts,
        "undersized_sectors": undersized,
        "min_bucket_size": min_bucket,
        "known_bias": (
            "Resolver-traffic rankings overrepresent consumer-facing web properties "
            "and underrepresent APIs, B2B services and machine-to-machine endpoints. "
            "Long confidentiality horizons concentrate in the underrepresented "
            "population, so this sampling systematically undercounts the highest-HNDL "
            "assets. Stated here so the limitation travels with the numbers."
        ),
        "bias_provenance": "inference",
    }
    assert_no_host_identifiers(manifest)
    return sectors, manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build a target list from a public ranking")
    p.add_argument("--ranking", type=Path, required=True, help="Tranco-style rank,domain CSV")
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    p.add_argument("--suffix", default=None, help="restrict to a ccTLD, e.g. .pl")
    p.add_argument("--top", type=int, default=None, help="highest rank to consider")
    p.add_argument("--min-bucket", type=int, default=5)
    p.add_argument("--targets-out", type=Path, default=REPO_ROOT / "config" / "targets.yaml")
    p.add_argument("--manifest-out", type=Path,
                   default=REPO_ROOT / "data" / "aggregates" / "selection_manifest.json")
    p.add_argument("--force", action="store_true", help="overwrite an existing targets file")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")

    if not args.ranking.exists():
        log.error("ranking file not found: %s", args.ranking)
        return 2
    if args.targets_out.exists() and not args.force:
        log.error("%s exists; pass --force to overwrite", args.targets_out)
        return 3

    sectors, manifest = select(args.ranking, args.rules, args.suffix, args.top, args.min_bucket)

    args.targets_out.write_text(
        "# Generated by collectors/select_targets.py. Git-ignored by design.\n"
        f"# source: {manifest['source']['file_name']} "
        f"sha256={manifest['source']['file_sha256'][:16]}...\n"
        + yaml.safe_dump({"sectors": {k: sorted(v) for k, v in sorted(sectors.items())}},
                         sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    write_json_atomic(args.manifest_out, manifest)

    log.info("targets: %s", args.targets_out)
    log.info("manifest: %s", args.manifest_out)
    for sector, n in sorted(manifest["sector_counts"].items(), key=lambda kv: -kv[1]):
        flag = "  (below min_bucket, will be suppressed at aggregation)" \
            if sector in manifest["undersized_sectors"] else ""
        log.info("  %-14s %5d%s", sector, n, flag)
    log.info("unclassified: %d of %d rows in scope",
             manifest["classification"]["unclassified"], manifest["source"]["rows_in_scope"])
    if manifest["classification"]["ambiguous_domains"]:
        log.warning("%d domain(s) matched rules from more than one sector; "
                    "resolved by config order",
                    manifest["classification"]["ambiguous_domains"])
        for rule_set, n in sorted(manifest["classification"]["rule_collisions"].items(),
                                  key=lambda kv: -kv[1]):
            log.warning("  %-60s %d", rule_set, n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
