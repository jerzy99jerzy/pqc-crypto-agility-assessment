#!/usr/bin/env python3
"""Passive certificate-dimension collector (Modality A).

Third-party estate, public data only. Zero packets are sent to any target
host by this module. Everything comes from Certificate Transparency.

Pipeline:
    targets.yaml (sector -> domains)
      -> crt.sh metadata
      -> leaf certificate fetch
      -> certparse dimensions            [measured]
      -> data/raw/certs/<host>.json      (git-ignored, host-level)
      -> data/aggregates/sectors.json    (committed, sector-level only)

Disclosure rule enforced in code: a sector bucket is emitted only if it holds
at least --min-bucket hosts. No host name ever leaves the raw store.

Usage:
    python -m collectors.passive_cert --targets config/targets.yaml
    python -m collectors.passive_cert --aggregate-only
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

try:  # allow both `python -m collectors.passive_cert` and direct execution
    from collectors.certparse import parse_certificate
    from collectors.crtsh import CrtShClient, RateLimiter, select_current_leaves
    from collectors.disclosure import assert_bucket_sizes, assert_no_host_identifiers
    from collectors.store import HostStore, write_json_atomic
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from collectors.certparse import parse_certificate
    from collectors.crtsh import CrtShClient, RateLimiter, select_current_leaves
    from collectors.disclosure import assert_bucket_sizes, assert_no_host_identifiers
    from collectors.store import HostStore, write_json_atomic

REPO_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = REPO_ROOT / "data" / "raw" / "certs"
AGG_DIR = REPO_ROOT / "data" / "aggregates"

log = logging.getLogger("passive_cert")


def load_targets(path: Path) -> dict[str, list[str]]:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    sectors = doc.get("sectors") or {}
    return {str(k): [str(d).strip().lower() for d in (v or [])] for k, v in sectors.items()}


def collect_host(client: CrtShClient, host: str, sector: str, leaves: int) -> dict:
    record = {
        "host": host,
        "sector": sector,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": "crt.sh",
        "modality": "passive",
        "certificates": [],
        "errors": [],
    }
    try:
        entries = client.search(host)
    except Exception as exc:
        record["errors"].append(f"search: {exc}")
        return record

    for entry in select_current_leaves(entries, limit=leaves):
        cid = entry.get("id")
        if cid is None:
            continue
        try:
            pem = client.fetch_certificate(int(cid))
        except Exception as exc:
            record["errors"].append(f"fetch {cid}: {exc}")
            continue
        parsed = parse_certificate(pem)
        d = parsed.to_dict()
        d["crtsh_id"] = cid
        d["ct_entry_timestamp"] = entry.get("entry_timestamp")
        record["certificates"].append(d)
    return record


def collect(targets: dict[str, list[str]], ttl: int, rate: float, leaves: int, force: bool) -> None:
    store = HostStore(RAW_DIR, ttl_seconds=ttl)
    client = CrtShClient(rate=RateLimiter(min_interval=rate))
    total = sum(len(v) for v in targets.values())
    done = 0
    for sector, hosts in targets.items():
        for host in hosts:
            done += 1
            if not force and store.is_fresh(host):
                log.info("[%d/%d] %s: fresh, skipping", done, total, host)
                continue
            log.info("[%d/%d] %s (%s)", done, total, host, sector)
            record = collect_host(client, host, sector, leaves)
            store.write(host, record)


def _key_bucket(cert: dict) -> str:
    alg = cert.get("key_algorithm") or "unknown"
    param = cert.get("key_parameter")
    if alg == "RSA" and param:
        return f"RSA-{param}"
    if alg == "EC" and param:
        return f"EC-{param}"
    return str(alg)


def aggregate(min_bucket: int) -> Path:
    """Collapse the host-level raw store into sector-level counts.

    Nothing host-identifying survives this function. Buckets smaller than
    min_bucket are dropped entirely rather than reported with n=1.
    """
    store = HostStore(RAW_DIR)
    per_sector: dict[str, dict] = defaultdict(
        lambda: {
            "hosts_observed": 0,
            "hosts_with_certificate": 0,
            "key_algorithms": Counter(),
            "signature_algorithms": Counter(),
            "quantum_vulnerable_key": Counter(),
            "valid_beyond_2030_milestone": Counter(),
            "validity_days_buckets": Counter(),
            "pqc_indicators_observed": 0,
        }
    )

    for rec in store.iter_records():
        sector = rec.get("sector") or "unclassified"
        agg = per_sector[sector]
        agg["hosts_observed"] += 1
        certs = [c for c in rec.get("certificates", []) if not c.get("parse_error")]
        if not certs:
            continue
        agg["hosts_with_certificate"] += 1
        cert = certs[0]  # most recently logged leaf represents current posture
        agg["key_algorithms"][_key_bucket(cert)] += 1
        agg["signature_algorithms"][str(cert.get("signature_algorithm"))] += 1
        agg["quantum_vulnerable_key"][str(cert.get("key_quantum_vulnerable"))] += 1
        agg["valid_beyond_2030_milestone"][str(cert.get("valid_beyond_2030_milestone"))] += 1
        vd = cert.get("validity_days")
        if isinstance(vd, int):
            bucket = "<=90d" if vd <= 90 else "91-398d" if vd <= 398 else ">398d"
            agg["validity_days_buckets"][bucket] += 1
        if cert.get("key_quantum_vulnerable") is False or (
            cert.get("signature_quantum_vulnerable") is False
        ):
            agg["pqc_indicators_observed"] += 1

    emitted, suppressed = {}, []
    for sector, agg in per_sector.items():
        if agg["hosts_observed"] < min_bucket:
            suppressed.append(sector)
            continue
        emitted[sector] = {k: (dict(v) if isinstance(v, Counter) else v) for k, v in agg.items()}

    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "modality": "A_passive_public_ct",
        "provenance": "measured",
        "disclosure_policy": {
            "granularity": "sector",
            "min_bucket_size": min_bucket,
            "suppressed_sectors": sorted(suppressed),
            "note": "host-level data stays in data/raw/ and is never committed",
        },
        "caveat": (
            "Certificate dimensions describe the served leaf certificate only. "
            "They say nothing about the negotiated TLS key exchange, and therefore "
            "nothing about PQC readiness of the key agreement. See README section "
            "'What this assessment will not tell you'."
        ),
        "sectors": emitted,
    }
    # Enforcement, not documentation: the scope statement fails closed here.
    assert_bucket_sizes({s: a["hosts_observed"] for s, a in emitted.items()}, min_bucket)
    assert_no_host_identifiers(payload)

    out = AGG_DIR / "sectors.json"
    write_json_atomic(out, payload)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Passive CT certificate collector")
    p.add_argument("--targets", type=Path, default=REPO_ROOT / "config" / "targets.yaml")
    p.add_argument("--ttl", type=int, default=7 * 24 * 3600, help="store freshness in seconds")
    p.add_argument("--rate", type=float, default=2.0, help="min seconds between crt.sh calls")
    p.add_argument("--leaves", type=int, default=2, help="certificates parsed per host")
    p.add_argument("--min-bucket", type=int, default=5, help="minimum hosts per emitted sector")
    p.add_argument("--force", action="store_true", help="ignore store freshness")
    p.add_argument("--aggregate-only", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )

    if not args.aggregate_only:
        if not args.targets.exists():
            log.error("targets file not found: %s (copy config/targets.example.yaml)", args.targets)
            return 2
        collect(load_targets(args.targets), args.ttl, args.rate, args.leaves, args.force)

    out = aggregate(args.min_bucket)
    log.info("sector aggregate written: %s", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
