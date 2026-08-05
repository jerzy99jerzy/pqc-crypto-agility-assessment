"""Cross-check: what the operator handed over against what is publicly logged.

This is the only available control on adversary A3 in `docs/THREAT-MODEL.md` -
the client who supplies a convenient dump. Nothing in a directory of
certificates can show that the directory is the estate, so the completeness of
a first-party set is `reported` and no amount of parsing changes that. What can
be done is to look for the same operator in a record they do not curate.

Certificate Transparency is that record. Every publicly trusted certificate
issued for their domains is in it, whether or not it made it into the dump.

**The asymmetry is the whole design.** Present in CT and absent from the dump is
a finding: a publicly trusted certificate exists for this operator and was not
declared. Present in the dump and absent from CT is not a finding at all: an
internal PKI issues certificates that never touch a public log, and treating
that as a discrepancy would generate noise proportional to how well-run the
internal PKI is. The two directions are counted separately and only one of them
is called a gap.

What this still cannot see: a host whose certificate is internally issued and
which was omitted from the dump is invisible to both sides. The check narrows
the gap; it does not close it, and the report says so.

Output is counts. Host identity is compared in memory and never written: the
result of a cross-check is "eleven publicly logged certificates were not in the
supplied set", never which eleven. The operator can reproduce the list locally
from their own two stores; a report that travels does not carry it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
from pathlib import Path

try:
    from ananke.collectors.disclosure import assert_no_host_identifiers
    from ananke.collectors.store import HostStore
except ImportError:  # pragma: no cover
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ananke.collectors.disclosure import assert_no_host_identifiers
    from ananke.collectors.store import HostStore

log = logging.getLogger("crosscheck")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "data" / "aggregates" / "estate_completeness.json"


def normalise(host: str) -> str:
    """Comparison form for a host name.

    A wildcard certificate covers the apex it is issued for, and a trailing dot
    is the same name; neither difference should register as a discrepancy.
    """
    return str(host).strip().lower().rstrip(".").removeprefix("*.")


def _hosts(store_dir: Path) -> set[str]:
    return {
        normalise(rec["host"])
        for rec in HostStore(store_dir).iter_records()
        if rec.get("host") and not str(rec["host"]).startswith("unidentified-")
    }


def compare(reported: set[str], public: set[str]) -> dict:
    """Counts only. The sets are compared here and discarded here.

    Normalises defensively rather than trusting the caller: a wildcard in CT
    against the declared apex is the single most likely false discrepancy, and
    a false "eleven undeclared certificates" is worse than no check, because it
    accuses the client of something the data does not show.
    """
    reported = {normalise(h) for h in reported}
    public = {normalise(h) for h in public}
    missing = public - reported
    internal_only = reported - public
    both = reported & public
    coverage = round(len(both) / len(public), 3) if public else None
    return {
        "reported_hosts": len(reported),
        "publicly_logged_hosts": len(public),
        "in_both": len(both),
        # The finding: publicly trusted certificates the operator did not declare.
        "publicly_logged_not_in_reported_set": len(missing),
        # Not a finding: internal PKI never reaches a public log.
        "reported_not_publicly_logged": len(internal_only),
        "public_coverage_of_reported_set": coverage,
        "interpretation": {
            "gap": "publicly_logged_not_in_reported_set is the only count that "
                   "indicates an incomplete declaration",
            "not_a_gap": "reported_not_publicly_logged is expected wherever an "
                         "internal PKI issues certificates and is not evidence "
                         "of anything",
            "blind_spot": "a host with an internally issued certificate that was "
                          "also omitted from the dump is invisible to both sides; "
                          "this check narrows the gap, it does not close it",
        },
    }


def run(reported_store: Path, public_store: Path, out: Path) -> dict:
    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "check": "estate_completeness",
        "provenance": "measured",
        "provenance_note": "the comparison is measured; what it bounds is the "
                           "reported completeness of the operator-supplied set",
        "result": compare(_hosts(reported_store), _hosts(public_store)),
        "disclosure_policy": {
            "granularity": "counts",
            "note": "host names are compared in memory and never written; the "
                    "operator can reproduce the list locally from both stores",
        },
    }
    # Counts only, but the guard runs anyway: this file is written into the
    # committed aggregates directory and every path into it is gated.
    assert_no_host_identifiers(payload)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Compare an operator-supplied estate against its public CT footprint")
    p.add_argument("--reported-store", type=Path, required=True,
                   help="raw store from --source local-pem")
    p.add_argument("--public-store", type=Path, required=True,
                   help="raw store from a CT collection over the same operator's domains")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
    for store in (args.reported_store, args.public_store):
        if not store.is_dir():
            log.error("not a store directory: %s", store)
            return 2

    payload = run(args.reported_store, args.public_store, args.out)
    r = payload["result"]
    log.info("declared %d, publicly logged %d, undeclared but public %d",
             r["reported_hosts"], r["publicly_logged_hosts"],
             r["publicly_logged_not_in_reported_set"])
    if r["publicly_logged_not_in_reported_set"]:
        log.warning("the supplied set is not the whole publicly visible estate")
    log.info("written: %s", args.out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
