#!/usr/bin/env python3
"""HNDL exposure scoring from observable proxies.

The model has no access to data classification, so it does not pretend to have
it. It combines measured certificate dimensions with one named assumption
(sector confidentiality horizon) and projects the result onto the 2030-12-31
regulatory milestone.

Every weight, horizon and threshold comes from ananke.scoring/weights.yaml. Nothing is
hardcoded here except the arithmetic.

Output per subject:
    exposure_years_beyond_milestone   how long data captured today must stay
                                      confidential after the point at which
                                      classical-only PK is no longer acceptable
    score / band                      weighted composite, with per-component
                                      contributions so the number can be argued
                                      with rather than believed

Usage:
    python scoring/hndl_score.py --from-store          # per-sector, from raw CT store
    python scoring/hndl_score.py --explain '{"sector":"finance","key_algorithm":"RSA", ...}'
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys
from pathlib import Path
from statistics import mean

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from ananke.collectors.disclosure import assert_bucket_sizes, assert_no_host_identifiers  # noqa: E402
from ananke.collectors.store import HostStore, write_json_atomic  # noqa: E402

log = logging.getLogger("hndl_score")
# Package data, addressed from the module rather than the repo root: an
# installed wheel has no repo root to walk up to.
DEFAULT_CONFIG = Path(__file__).resolve().parent / "weights.yaml"
RAW_DIR = REPO_ROOT / "data" / "raw" / "certs"
AGG_DIR = REPO_ROOT / "data" / "aggregates"

DAYS_PER_YEAR = 365.2425


def load_config(path: Path = DEFAULT_CONFIG) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def horizon_for(sector: str, cfg: dict) -> int:
    h = cfg["confidentiality_horizon_years"]
    return int(h["by_sector"].get(sector, h["default"]))


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def milestone_date(cfg: dict) -> dt.date:
    m = cfg["milestone"]["date"]
    return dt.date.fromisoformat(m) if isinstance(m, str) else m


def exposure_years(horizon: int, today: dt.date, milestone: dt.date) -> float:
    """Years by which the required confidentiality window outlives the milestone."""
    exposure_end = today + dt.timedelta(days=int(horizon * DAYS_PER_YEAR))
    return max(0.0, (exposure_end - milestone).days / DAYS_PER_YEAR)


def horizon_pressure_cap(cfg: dict, today: dt.date | None = None) -> tuple[float, str]:
    """Saturation cap for the horizon_pressure component.

    Two ways to set it:

      horizon_pressure_cap_years: derived   (default)
          cap = exposure of the longest configured sector horizon. By
          construction no configured sector can saturate, and the cap cannot
          drift out of sync when a horizon is edited. It also re-normalises as
          the milestone approaches, which is correct: the same 30-year horizon
          buys more exposure every year that passes.

      horizon_pressure_cap_years: <number>
          fixed. Kept because an analyst may deliberately want saturation, for
          instance to state that beyond 20 years the distinction stops being
          decision-relevant. validate_config() will still report which sectors
          saturate, so the choice is explicit rather than accidental.
    """
    today = today or dt.date.today()
    milestone = milestone_date(cfg)
    raw = cfg["parameters"].get("horizon_pressure_cap_years", "derived")

    if isinstance(raw, (int, float)):
        return float(raw), "fixed"

    horizons = cfg["confidentiality_horizon_years"]
    longest = max([*horizons["by_sector"].values(), horizons["default"]])
    cap = exposure_years(longest, today, milestone)
    # If every configured horizon expires before the milestone, every exposure
    # is zero and the cap is unused; keep it positive to avoid a divide by zero.
    return (cap if cap > 0 else 1.0), "derived"


def validate_config(cfg: dict, today: dt.date | None = None) -> list[dict]:
    """Return configuration issues as {severity, message}.

    Severity matters because the two failure modes are not equivalent. Top-end
    saturation silently collapses the sectors the model exists to rank, so it is
    an error. Bottom-end flooring is an expected consequence of horizons shorter
    than the distance to the milestone, so it is a warning that has to be stated
    rather than a defect to fix.
    """
    today = today or dt.date.today()
    milestone = milestone_date(cfg)
    issues: list[dict] = []

    cap, mode = horizon_pressure_cap(cfg, today)
    horizons = cfg["confidentiality_horizon_years"]["by_sector"]

    saturating = [s for s, h in horizons.items() if exposure_years(h, today, milestone) > cap]
    if saturating:
        issues.append({"severity": "error", "message": (
            f"horizon_pressure saturates ({mode} cap {cap:.2f}y) for: "
            f"{', '.join(sorted(saturating))}. These sectors receive an identical "
            "component value and stop being distinguishable from each other."
        )})

    floored = [s for s, h in horizons.items() if exposure_years(h, today, milestone) == 0.0]
    if len(floored) > 1:
        issues.append({"severity": "warning", "message": (
            f"horizon_pressure floors at zero for: {', '.join(sorted(floored))}. "
            "Expected where the horizon is shorter than the distance to the "
            "milestone: those sectors carry no HNDL exposure at all. They are not "
            "distinguishable from each other on this component, by construction."
        )})

    weights = cfg["weights"]
    if any(v < 0 for v in weights.values()):
        issues.append({"severity": "error",
                       "message": "negative weight in scoring/weights.yaml"})
    if sum(weights.values()) <= 0:
        issues.append({"severity": "error", "message":
                       "weights sum to zero; the composite score would be undefined"})

    bands = cfg["bands"]
    if [b["min"] for b in bands] != sorted(b["min"] for b in bands):
        issues.append({"severity": "error",
                       "message": "bands are not in ascending order of `min`"})

    return issues


def score_subject(subject: dict, cfg: dict, today: dt.date | None = None) -> dict:
    """Score one subject.

    subject keys (all optional, missing ones are reported as unknown):
        sector, key_algorithm, key_quantum_vulnerable,
        signature_quantum_vulnerable, valid_beyond_2030_milestone, validity_days
    """
    today = today or dt.date.today()
    milestone = milestone_date(cfg)
    w = cfg["weights"]
    p = cfg["parameters"]

    sector = subject.get("sector") or "unclassified"
    horizon = horizon_for(sector, cfg)
    exposure = exposure_years(horizon, today, milestone)
    cap, cap_mode = horizon_pressure_cap(cfg, today)

    components: dict[str, dict] = {}

    key_vuln = subject.get("key_quantum_vulnerable")
    components["key_vulnerability"] = {
        "value": 1.0 if key_vuln else (0.0 if key_vuln is False else 0.5),
        "provenance": "measured" if key_vuln is not None else "unknown",
        "basis": subject.get("key_algorithm"),
    }

    sig_vuln = subject.get("signature_quantum_vulnerable")
    components["signature_vulnerability"] = {
        "value": 1.0 if sig_vuln else (0.0 if sig_vuln is False else 0.5),
        "provenance": "measured" if sig_vuln is not None else "unknown",
        "basis": subject.get("signature_algorithm"),
    }

    components["horizon_pressure"] = {
        "value": _clamp01(exposure / cap),
        "provenance": "assumption",
        "basis": (
            f"sector horizon {horizon}y -> {exposure:.1f}y beyond milestone, "
            f"normalised against {cap_mode} cap {cap:.2f}y"
        ),
    }

    beyond = subject.get("valid_beyond_2030_milestone")
    components["certificate_outlives_milestone"] = {
        "value": 1.0 if beyond else (0.0 if beyond is False else 0.5),
        "provenance": "measured" if beyond is not None else "unknown",
        "basis": subject.get("not_after"),
    }

    vd = subject.get("validity_days")
    threshold = int(p["agility_validity_days_threshold"])
    components["rotation_agility"] = {
        "value": _clamp01(vd / (threshold * 2.0)) if isinstance(vd, int) else 0.5,
        "provenance": "inference",
        "basis": f"validity_days={vd} vs threshold {threshold}",
    }

    total_weight = sum(w.values())
    contributions = {
        k: (w[k] * v["value"]) / total_weight for k, v in components.items()
    }
    score = sum(contributions.values())

    band = cfg["bands"][0]["name"]
    for b in cfg["bands"]:
        if score >= float(b["min"]):
            band = b["name"]

    return {
        "sector": sector,
        "confidentiality_horizon_years": horizon,
        "horizon_provenance": "assumption",
        "milestone": milestone.isoformat(),
        "exposure_years_beyond_milestone": round(exposure, 2),
        "horizon_pressure_cap_years": round(cap, 2),
        "horizon_pressure_cap_mode": cap_mode,
        "score": round(score, 4),
        "band": band,
        "components": {
            k: {**v, "weight": w[k], "contribution": round(contributions[k], 4)}
            for k, v in components.items()
        },
        "model_version": cfg.get("version"),
    }


def score_from_store(cfg: dict, min_bucket: int) -> dict:
    """Score the raw CT store and emit sector-level distributions only."""
    store = HostStore(RAW_DIR)
    per_sector: dict[str, list[dict]] = {}
    for rec in store.iter_records():
        certs = [c for c in rec.get("certificates", []) if not c.get("parse_error")]
        if not certs:
            continue
        subject = dict(certs[0])
        subject["sector"] = rec.get("sector") or "unclassified"
        per_sector.setdefault(subject["sector"], []).append(score_subject(subject, cfg))

    sectors, suppressed = {}, []
    for sector, scores in per_sector.items():
        if len(scores) < min_bucket:
            suppressed.append(sector)
            continue
        values = [s["score"] for s in scores]
        bands: dict[str, int] = {}
        for s in scores:
            bands[s["band"]] = bands.get(s["band"], 0) + 1
        sectors[sector] = {
            "n": len(scores),
            "score_mean": round(mean(values), 4),
            "score_min": round(min(values), 4),
            "score_max": round(max(values), 4),
            "band_distribution": bands,
            "confidentiality_horizon_years": scores[0]["confidentiality_horizon_years"],
            "exposure_years_beyond_milestone": scores[0]["exposure_years_beyond_milestone"],
        }

    cap, cap_mode = horizon_pressure_cap(cfg)
    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "model_version": cfg.get("version"),
        "provenance_note": (
            "Certificate dimensions are measured. Sector confidentiality horizon is an "
            "assumption stated in scoring/weights.yaml. The composite score is an "
            "inference built from both and inherits the weaker label."
        ),
        "model_parameters": {
            "horizon_pressure_cap_years": round(cap, 2),
            "horizon_pressure_cap_mode": cap_mode,
            "weights": dict(cfg["weights"]),
        },
        "config_issues": validate_config(cfg),
        "disclosure_policy": {"granularity": "sector", "min_bucket_size": min_bucket,
                              "suppressed_sectors": sorted(suppressed)},
        "sectors": sectors,
    }
    assert_bucket_sizes({s: v["n"] for s, v in sectors.items()}, min_bucket)
    assert_no_host_identifiers(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="HNDL exposure scoring")
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("--from-store", action="store_true", help="score data/raw/certs/")
    p.add_argument("--explain", help="score a single JSON subject and print the breakdown")
    p.add_argument("--validate-config", action="store_true",
                   help="report saturation, floors and weight problems, then exit")
    p.add_argument("--min-bucket", type=int, default=5)
    p.add_argument("--out", type=Path, default=AGG_DIR / "hndl_sector_scores.json")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
    cfg = load_config(args.config)
    issues = validate_config(cfg)

    if args.validate_config:
        cap, mode = horizon_pressure_cap(cfg)
        print(f"horizon_pressure cap: {cap:.2f}y ({mode})")
        for issue in issues:
            print(f"{issue['severity'].upper():<8}{issue['message']}")
        errors = [i for i in issues if i["severity"] == "error"]
        print(f"{len(errors)} error(s), {len(issues) - len(errors)} warning(s)")
        return 1 if errors else 0

    for issue in issues:
        log.warning("config [%s]: %s", issue["severity"], issue["message"])

    if args.explain:
        print(json.dumps(score_subject(json.loads(args.explain), cfg), indent=2))
        return 0

    if args.from_store:
        payload = score_from_store(cfg, args.min_bucket)
        write_json_atomic(args.out, payload)
        print(json.dumps(payload, indent=2))
        log.info("written: %s", args.out)
        return 0

    p.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
