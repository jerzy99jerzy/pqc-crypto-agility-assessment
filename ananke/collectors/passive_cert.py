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
    from ananke.collectors.certparse import parse_certificate
    from ananke.collectors.crtsh import CrtShClient, RateLimiter
    from ananke.collectors.disclosure import (
    HOSTNAME_RE,
    DisclosureViolation,
    assert_bucket_sizes,
    assert_no_host_identifiers,
)
    from ananke.collectors.sources import CertificateSource, CrtShSource, LocalPemSource
    from ananke.config import load_milestone
    from ananke.collectors.store import HostStore, write_json_atomic
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ananke.collectors.certparse import parse_certificate
    from ananke.collectors.crtsh import CrtShClient, RateLimiter
    from ananke.collectors.disclosure import (
    DisclosureViolation,
    assert_bucket_sizes,
    assert_no_host_identifiers,
)
    from ananke.collectors.sources import CertificateSource, CrtShSource, LocalPemSource
    from ananke.config import load_milestone
    from ananke.collectors.store import HostStore, write_json_atomic

REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = REPO_ROOT / "data" / "raw" / "certs"
AGG_DIR = REPO_ROOT / "data" / "aggregates"

log = logging.getLogger("passive_cert")


def load_targets(path: Path) -> dict[str, list[str]]:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    sectors = doc.get("sectors") or {}
    return {str(k): [str(d).strip().lower() for d in (v or [])] for k, v in sectors.items()}


def collect(source: CertificateSource, ttl: int, force: bool) -> int:
    """Drain a source into the raw store. Returns the number of records written.

    Freshness is a store concern, not a source concern, so the skip predicate is
    injected here rather than reimplemented per source.
    """
    store = HostStore(RAW_DIR, ttl_seconds=ttl)
    if hasattr(source, "skip") and source.skip is None and not force:
        source.skip = store.is_fresh
    written = 0
    for record in source.iter_records():
        store.write(record["host"], record)
        written += 1
    return written


def _expiry_date(cert: dict) -> dt.date | None:
    """not_after as a date, tolerant of both isoformat variants; None if absent.

    The decision split recomputes from the date rather than trusting the
    stored boolean, so a store collected under one milestone reclassifies
    correctly when aggregated under another.
    """
    raw = cert.get("not_after")
    if not raw:
        return None
    try:
        return dt.datetime.fromisoformat(str(raw).replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _key_bucket(cert: dict) -> str:
    alg = cert.get("key_algorithm") or "unknown"
    param = cert.get("key_parameter")
    if alg == "RSA" and param:
        return f"RSA-{param}"
    if alg == "EC" and param:
        return f"EC-{param}"
    return str(alg)


class MixedModalityError(RuntimeError):
    """Raised when one store holds records from more than one modality.

    "40% RSA" across a public CT sample and across one operator's declared
    estate are different statements. Silently summing them produces a number
    with no referent, so aggregation refuses rather than picks.
    """


# Record tag -> (aggregate label, provenance, first party). An unrecognised tag
# resolves to the conservative row: not first party, so bucket suppression stays
# on. A store written by an older version carries no tag at all and is treated
# as passive CT, which is what it was.
_REGIMES = {
    "passive": ("A_passive_public_ct", "measured", False),
    "first_party_offline": ("D_first_party_offline", "reported", True),
}


def _regime(records: list[dict]) -> tuple[str, str, bool]:
    """Return (aggregate modality, provenance, first_party) for one store."""
    tags = {r.get("modality") or "passive" for r in records}
    if len(tags) > 1:
        raise MixedModalityError(
            "raw store holds several modalities: "
            + ", ".join(sorted(tags))
            + ". Collect each source into its own store."
        )
    tag = tags.pop() if tags else "passive"
    return _REGIMES.get(tag, (tag, "measured", False))


def aggregate(min_bucket: int, milestone: dt.date | None = None) -> Path:
    """Collapse the host-level raw store into sector-level counts.

    Nothing host-identifying survives this function. Buckets smaller than
    min_bucket are dropped entirely rather than reported with n=1.
    """
    milestone = milestone or load_milestone()
    store = HostStore(RAW_DIR)
    records = list(store.iter_records())
    modality, provenance, first_party = _regime(records)
    # Minimum bucket size protects third parties from being identified through
    # a sector of one. A first-party estate has nobody to protect from the
    # report's own commissioner, and suppression there would delete the
    # deliverable rather than protect anyone. Only a source may assert this;
    # there is deliberately no flag that turns it off for CT data.
    effective_min = 1 if first_party else min_bucket
    per_sector: dict[str, dict] = defaultdict(
        lambda: {
            "hosts_observed": 0,
            "hosts_with_certificate": 0,
            "key_algorithms": Counter(),
            "signature_algorithms": Counter(),
            "quantum_vulnerable_key": Counter(),
            "valid_beyond_milestone": Counter(),
            "validity_days_buckets": Counter(),
            "pqc_indicators_observed": 0,
            # Decision layer (sprint 11): the split a plan is built from.
            # Self-resolving: expiry on or before the milestone, so normal
            # renewal replaces it. Intervention: no renewal is scheduled that
            # would, so each is a deliberate change. Counted per host from
            # not_after against the configured milestone, never from the
            # stored boolean, so re-aggregating with a different milestone
            # reclassifies without recollecting.
            "self_resolving_via_rotation": 0,
            "intervention_required": 0,
            "intervention_expiry_years": Counter(),
            "rotation_bands": Counter(),
            "validity_days_all": [],
            "issuers": Counter(),
        }
    )

    for rec in records:
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
        beyond = cert.get("valid_beyond_milestone", cert.get("valid_beyond_2030_milestone"))
        agg["valid_beyond_milestone"][str(beyond)] += 1
        expiry = _expiry_date(cert)
        if expiry is not None:
            if expiry <= milestone:
                agg["self_resolving_via_rotation"] += 1
            else:
                agg["intervention_required"] += 1
                agg["intervention_expiry_years"][str(expiry.year)] += 1
        vd = cert.get("validity_days")
        if isinstance(vd, int):
            bucket = "<=90d" if vd <= 90 else "91-398d" if vd <= 398 else ">398d"
            agg["validity_days_buckets"][bucket] += 1
            band = ("<=100d" if vd <= 100 else "101-400d" if vd <= 400
                    else "401-1100d" if vd <= 1100 else ">1100d")
            agg["rotation_bands"][band] += 1
            agg["validity_days_all"].append(vd)
        # Issuer distribution answers "how many CA relationships must change
        # to change issuance policy". issuer_o only, never issuer_cn: on a
        # self-signed certificate the issuer IS the subject, so counting CNs
        # walks host identity straight into the aggregate - caught by the
        # sprint 2 suppression test the moment this counter was added. An
        # organisation name is what the field is for; a host-shaped value is
        # dropped rather than published, and the guard re-checks downstream.
        issuer = cert.get("issuer_o")
        if issuer and not HOSTNAME_RE.search(str(issuer)):
            agg["issuers"][str(issuer)[:64]] += 1
        else:
            agg["issuers"]["(self-signed or unnamed)"] += 1
        if cert.get("key_quantum_vulnerable") is False or (
            cert.get("signature_quantum_vulnerable") is False
        ):
            agg["pqc_indicators_observed"] += 1

    emitted, suppressed = {}, []
    for sector, agg in per_sector.items():
        if agg["hosts_observed"] < effective_min:
            suppressed.append(sector)
            continue
        days = sorted(agg.pop("validity_days_all"))
        stats = None
        if days:
            mid = len(days) // 2
            median = days[mid] if len(days) % 2 else (days[mid - 1] + days[mid]) / 2
            stats = {"median": median, "min": days[0], "max": days[-1],
                     "rotations_before_milestone": round(
                         max((milestone - dt.date.today()).days, 0) / median, 2)}
        emitted[sector] = {k: (dict(v) if isinstance(v, Counter) else v) for k, v in agg.items()}
        emitted[sector]["rotation_stats"] = stats

    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "modality": modality,
        "provenance": provenance,
        "milestone": {"date": milestone.isoformat(),
                      "note": "decision counters computed against this date"},
        "disclosure_policy": {
            # Sector in both regimes: this file holds counts, never host rows.
            # First-party status changes the suppression threshold, not the
            # granularity, and saying otherwise would misdescribe the artefact.
            "granularity": "sector",
            "min_bucket_size": effective_min,
            "first_party_estate": first_party,
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
    # Keys, not just values: sector names are dictionary keys in the payload
    # and the guard's value walk never sees them. A second, independent check
    # here means a future source that forgets validate_sector still cannot
    # publish a host-shaped or markup-bearing sector (sprint 10 review, S1/S2).
    from ananke.collectors.sources import SectorLabelError, validate_sector
    for name in emitted:
        try:
            validate_sector(name)
        except SectorLabelError as exc:
            raise DisclosureViolation(str(exc)) from exc
    assert_bucket_sizes({s: a["hosts_observed"] for s, a in emitted.items()}, effective_min)
    assert_no_host_identifiers(payload)

    out = AGG_DIR / "sectors.json"
    write_json_atomic(out, payload)
    return out


def _build_source(args) -> CertificateSource | None:
    """Turn parsed arguments into a source, or None when the arguments are unusable."""
    if args.source == "local-pem":
        if not args.pem_dir or not args.pem_dir.is_dir():
            log.error("--source local-pem requires --pem-dir pointing at a directory")
            return None
        if not args.sector:
            log.error("--source local-pem requires --sector: a certificate does not "
                      "carry the operator's sector")
            return None
        return LocalPemSource(args.pem_dir, args.sector)
    if not args.targets.exists():
        log.error("targets file not found: %s (copy config/targets.example.yaml)", args.targets)
        return None
    return CrtShSource(
        load_targets(args.targets),
        CrtShClient(rate=RateLimiter(min_interval=args.rate)),
        leaves=args.leaves,
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Passive CT certificate collector")
    p.add_argument("--source", choices=["crtsh", "local-pem"], default="crtsh",
                   help="crtsh: third-party estate via CT. local-pem: an operator's own "
                        "certificates from a directory, offline, no network peer.")
    p.add_argument("--pem-dir", type=Path, help="directory of PEM/DER files (--source local-pem)")
    p.add_argument("--sector", help="sector label for --source local-pem")
    p.add_argument("--targets", type=Path, default=REPO_ROOT / "config" / "targets.yaml")
    p.add_argument("--ttl", type=int, default=7 * 24 * 3600, help="store freshness in seconds")
    p.add_argument("--rate", type=float, default=2.0, help="min seconds between crt.sh calls")
    p.add_argument("--leaves", type=int, default=2, help="certificates parsed per host")
    p.add_argument("--min-bucket", type=int, default=5, help="minimum hosts per emitted sector")
    p.add_argument("--milestone", type=dt.date.fromisoformat, default=None,
                   help="compliance milestone (YYYY-MM-DD); default from weights.yaml")
    p.add_argument("--force", action="store_true", help="ignore store freshness")
    p.add_argument("--aggregate-only", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )

    if not args.aggregate_only:
        source = _build_source(args)
        if source is None:
            return 2
        collect(source, args.ttl, args.force)

    out = aggregate(args.min_bucket, milestone=args.milestone)
    log.info("sector aggregate written: %s", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
