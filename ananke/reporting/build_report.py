#!/usr/bin/env python3
"""Build the assessment report from committed aggregates.

Reads only data/aggregates/. It has no access to the raw host-level store, by
construction rather than by discipline: a report generator that cannot read
host data cannot leak host data.

Before writing, the rendered markdown is scanned for anything resembling a
hostname. Hosts declared in config/reference_hosts.yaml are permitted, since
naming a positive control is part of the method. Anything else fails the build.

Usage:
    python reporting/build_report.py
    python reporting/build_report.py --out docs/report.md
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from ananke.collectors.disclosure import DisclosureViolation, scan_text  # noqa: E402

log = logging.getLogger("build_report")
AGG_DIR = REPO_ROOT / "data" / "aggregates"

LEGEND = """| Label | Meaning |
|---|---|
| `[measured]` | Read from a certificate, a handshake or a log, without interpretation |
| `[inference]` | Derived from observable proxies |
| `[assumption]` | Chosen by the analyst, defensible but not observed |
| `[speculation]` | Explicitly uncertain, carried through rather than resolved |

A composite value inherits the weakest label of its inputs."""

NOT_TOLD = """- Cryptography at rest.
- HSMs.
- Internal PKI, except indirectly through endpoint certificate inventory in the detection layer.
- Code, embedded libraries, pinned certificates inside applications.
- The negotiated key exchange group of third-party services. That is not observable from certificate data and would require an active handshake, which is not performed against third-party estate.

A certificate using RSA says nothing about whether the same service already negotiates a hybrid group. Different layers. Conflating them is the most common error in this space."""


def load(name: str) -> dict | None:
    path = AGG_DIR / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def reference_hosts() -> set[str]:
    path = REPO_ROOT / "config" / "reference_hosts.yaml"
    if not path.exists():
        return set()
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: set[str] = set()
    for category in ("self", "reference"):
        for host in doc.get(category) or []:
            out.add(str(host).strip().lower())
    return out


def _pct(part: int, whole: int) -> str:
    return f"{(100.0 * part / whole):.0f}%" if whole else "n/a"


def section_selection(manifest: dict | None) -> str:
    if not manifest:
        return (
            "## 1. Selection and denominator\n\n"
            "**No selection manifest present.** No population figure is reported in "
            "this run, because a percentage without a stated denominator is not a "
            "finding. Run `collectors/select_targets.py` against a pinned public "
            "ranking to generate one.\n"
        )
    src, cls = manifest["source"], manifest["classification"]
    lines = [
        "## 1. Selection and denominator",
        "",
        f"Source ranking `{src['file_name']}`, SHA-256 `{src['file_sha256'][:16]}...`, "
        f"{src['rows_in_scope']} rows in scope after filters "
        f"`{manifest['filters']}`. `[measured]`",
        "",
        f"Classification ruleset `{cls['rules_file']}`, SHA-256 "
        f"`{cls['rules_sha256'][:16]}...`. Unclassified: {cls['unclassified']} rows. "
        "`[inference]`",
        "",
        "| Sector | Selected |",
        "|---|---:|",
    ]
    for sector, n in sorted(manifest["sector_counts"].items(), key=lambda kv: -kv[1]):
        flag = " (below minimum bucket, suppressed downstream)" \
            if sector in manifest.get("undersized_sectors", []) else ""
        lines.append(f"| {sector}{flag} | {n} |")
    ambiguous = cls.get("ambiguous_domains", 0)
    if ambiguous:
        lines += [
            "",
            f"**Classification ambiguity** `[measured]`: {ambiguous} domain(s) matched "
            "rules from more than one sector and were resolved by config order. "
            "Colliding rule sets, with counts:",
            "",
        ]
        for rule_set, n in sorted(cls.get("rule_collisions", {}).items(), key=lambda kv: -kv[1]):
            lines.append(f"- `{rule_set}` : {n}")
    lines += ["", f"**Known sampling bias** `[{manifest.get('bias_provenance', 'inference')}]`: "
              f"{manifest['known_bias']}", ""]
    return "\n".join(lines)


def section_measured(sectors: dict | None) -> str:
    if not sectors:
        return "## 2. Measured certificate dimensions\n\nNo passive aggregate present.\n"
    lines = [
        "## 2. Measured certificate dimensions `[measured]`",
        "",
        f"Modality: {sectors.get('modality')}. Generated {sectors.get('generated_at')}.",
        "",
        "| Sector | Hosts | With cert | Quantum-vulnerable key | Valid beyond 2030 | PQC indicators |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for sector, agg in sorted(sectors["sectors"].items()):
        n = agg["hosts_with_certificate"]
        vuln = agg["quantum_vulnerable_key"].get("True", 0)
        beyond = agg["valid_beyond_2030_milestone"].get("True", 0)
        lines.append(
            f"| {sector} | {agg['hosts_observed']} | {n} | {vuln} ({_pct(vuln, n)}) "
            f"| {beyond} ({_pct(beyond, n)}) | {agg['pqc_indicators_observed']} |"
        )
    policy = sectors.get("disclosure_policy", {})
    lines += [
        "",
        f"Disclosure policy: {policy.get('granularity')} granularity, minimum bucket "
        f"{policy.get('min_bucket_size')}, suppressed: "
        f"{', '.join(policy.get('suppressed_sectors') or []) or 'none'}.",
        "",
        "Key algorithm distribution:",
        "",
    ]
    for sector, agg in sorted(sectors["sectors"].items()):
        dist = ", ".join(f"{k}: {v}" for k, v in sorted(agg["key_algorithms"].items()))
        lines.append(f"- **{sector}**: {dist}")
    lines += ["", f"_{sectors.get('caveat', '')}_", ""]
    return "\n".join(lines)


def section_scores(scores: dict | None) -> str:
    if not scores:
        return "## 3. HNDL exposure\n\nNo scoring output present.\n"
    params = scores.get("model_parameters", {})
    lines = [
        "## 3. HNDL exposure `[inference]`",
        "",
        f"Model version {scores.get('model_version')}. Horizon pressure cap "
        f"{params.get('horizon_pressure_cap_years')}y "
        f"({params.get('horizon_pressure_cap_mode')}).",
        "",
        "| Sector | n | Exposure beyond milestone | Mean score | Bands |",
        "|---|---:|---:|---:|---|",
    ]
    ranked = sorted(scores["sectors"].items(), key=lambda kv: -kv[1]["score_mean"])
    for sector, agg in ranked:
        bands = ", ".join(f"{k}: {v}" for k, v in sorted(agg["band_distribution"].items()))
        lines.append(
            f"| {sector} | {agg['n']} | {agg['exposure_years_beyond_milestone']}y "
            f"| {agg['score_mean']} | {bands} |"
        )
    lines += ["", f"_{scores.get('provenance_note', '')}_", ""]
    issues = scores.get("config_issues") or []
    if issues:
        lines.append("Model configuration notes, reproduced rather than hidden:")
        lines.append("")
        for issue in issues:
            lines.append(f"- **{issue['severity']}**: {issue['message']}")
        lines.append("")
    return "\n".join(lines)


def section_active(active: dict | None) -> str:
    if not active:
        return (
            "## 4. Active PQC demonstration\n\n"
            "No handshake output present. Requires OpenSSL 3.5 or later and hosts "
            "declared in `config/reference_hosts.yaml`.\n"
        )
    env = active.get("environment", {})
    lines = [
        "## 4. Active PQC demonstration `[measured]`",
        "",
        f"Client: OpenSSL {env.get('openssl_version')}. "
        f"{active.get('scope_statement', '')}",
        "",
        "| Target | Category | Negotiated group | Hybrid | HRR inferred |",
        "|---|---|---|---|---|",
    ]
    for r in active.get("results", []):
        lines.append(
            f"| {r['host']} | {r.get('allowlist_category')} | "
            f"{r.get('negotiated_group') or 'none'} | "
            f"{'yes' if r.get('pqc_hybrid_negotiated') else 'no'} | "
            f"{'yes' if r.get('hello_retry_request_inferred') else 'no'} |"
        )
    lines += [
        "",
        "HelloRetryRequest is inferred from the client sending ClientHello twice, "
        "and is labelled `[inference]` in the underlying record rather than "
        "presented as measured.",
        "",
    ]
    return "\n".join(lines)


def section_capability(cap: dict | None) -> str:
    if not cap:
        return (
            "## 5. Endpoint crypto capability\n\n"
            "No capability analysis present. Run `inventory/pqc_capability.py` "
            "against a software inventory export to answer the question that "
            "gates the plan: on how many hosts is the crypto stack capable of a "
            "hybrid key exchange at all.\n"
        )
    totals = cap["totals"]
    lines = [
        "## 5. Endpoint crypto capability `[measured]`, verdicts `[inference]`",
        "",
        f"Export `{cap['source_file']}`: {totals['rows_in_export']} rows, "
        f"{totals['rows_matched_to_a_crypto_library']} matched a crypto library, "
        f"{totals['distinct_devices_in_export']} distinct devices.",
        "",
        "| Library | Version | Verdict | Basis | Threshold provenance | Rows | Devices |",
        "|---|---|---|---|---|---:|---:|",
    ]
    for f in cap["findings"]:
        lines.append(
            f"| {f['library']} | {f['version']} | {f['verdict']} | {f['reason']} "
            f"| {f['threshold_provenance']} | {f['rows']} | {f['devices']} |"
        )
    lines += [
        "",
        f"By row: {cap['verdict_summary_by_row']}.",
        "",
        f"_{cap['caveat']}_",
        "",
        f"_{cap['unknown_note']}_",
        "",
    ]
    return "\n".join(lines)


def build() -> str:
    sectors = load("sectors.json")
    scores = load("hndl_sector_scores.json")
    manifest = load("selection_manifest.json")
    active = load("handshake_demo.json")
    capability = load("pqc_capability.json")

    parts = [
        "# PQC Crypto-Agility Assessment: Report",
        "",
        f"Generated {dt.datetime.now(dt.timezone.utc).date().isoformat()} from committed "
        "aggregates. Host-level data was not read by this generator and is not "
        "available to it.",
        "",
        "## 0. Provenance legend",
        "",
        LEGEND,
        "",
        section_selection(manifest),
        section_measured(sectors),
        section_scores(scores),
        section_active(active),
        section_capability(capability),
        "## 6. What this assessment does not tell you",
        "",
        NOT_TOLD,
        "",
        "## 7. Scope",
        "",
        "Third-party estate: public Certificate Transparency data only, no active "
        "traffic. Active handshakes: operator-owned infrastructure and declared "
        "public reference implementations only, enforced by allowlist in code. "
        "Aggregation by sector with a minimum bucket size. No organisation is named "
        "next to a vulnerability finding.",
        "",
    ]
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build the assessment report")
    p.add_argument("--out", type=Path, default=REPO_ROOT / "docs" / "report.md")
    p.add_argument("--print", action="store_true", help="write to stdout as well")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")

    text = build()
    suspicious = scan_text(text, extra_allowed=reference_hosts())
    if suspicious:
        raise DisclosureViolation(
            "report contains host-like tokens that are not declared reference hosts: "
            f"{sorted(set(suspicious))}"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    log.info("report written: %s (%d bytes)", args.out, len(text))
    if args.print:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
