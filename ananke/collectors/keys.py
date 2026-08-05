"""Cryptography at rest, to the extent it is observable at all.

"We do not see cryptography at rest" was true of the pipeline and false as a
statement about the problem, because at rest is four different things and only
two of them are post-quantum problems.

**Bulk data encryption is not one of them.** Volumes, databases and object
stores are encrypted with AES. Grover halves the effective strength, so AES-256
retains 128 bits and needs no migration. This is most of what an organisation
means by "encrypted at rest", and saying nothing about it lets a client assume
the worst about the part that is fine.

**The wrapping layer is.** Envelope encryption puts data under a symmetric data
key and wraps that key with an asymmetric key encryption key, usually RSA or
EC. A quantum adversary does not break the data; it unwraps the key. That KEK
is enumerable through every managed key service, by metadata alone, with no
agent and without the key material ever leaving the vault.

**Long-lived signatures are, on a different clock.** A document that must stay
verifiable in 2040 and is signed today with RSA-2048 is exposed to forgery
after a cryptographically relevant quantum computer exists, which is not
harvest-now-decrypt-later and is not what `hndl_score` measures. Signing keys
are counted separately here for that reason; conflating the two clocks would
produce a number that means nothing for either.

**Application-layer cryptography is not observable** and this module does not
pretend otherwise.

Input is an export the operator produces themselves - Azure Resource Graph,
`aws kms list-keys` plus `describe-key`, GCP KMS list - so the engagement needs
no credentials into their key management. Provenance is therefore `reported`,
exactly as for the offline certificate estate: each record is parsed here, the
completeness of the export is the operator's claim.

Output is counts. Key identifiers, vault names and key ring paths are read for
grouping and never written.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
from collections import Counter
from pathlib import Path

try:
    from ananke.collectors.disclosure import assert_no_host_identifiers
    from ananke.collectors.sources import validate_sector
    from ananke.config import load_milestone
except ImportError:  # pragma: no cover
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ananke.collectors.disclosure import assert_no_host_identifiers
    from ananke.collectors.sources import validate_sector
    from ananke.config import load_milestone

log = logging.getLogger("keys")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "data" / "aggregates" / "key_inventory.json"

# Algorithm families. Tri-state throughout: an unrecognised family resolves to
# None and is reported as unknown, never as safe. This is the F1 failure mode
# from sprint 6 arriving on a new input, and the one this project cannot afford
# to repeat, because the product is a number somebody will budget against.
_VULNERABLE = {"rsa", "rsa-hsm", "ec", "ec-hsm", "ecdsa", "ecdh", "dsa", "dh"}
_QUANTUM_SAFE = {"ml-dsa", "mldsa", "dilithium", "ml-kem", "mlkem", "kyber",
                 "slh-dsa", "slhdsa", "sphincs+", "xmss", "lms"}
# Symmetric: in scope for the inventory, out of scope for migration. Counted so
# the report can say "this part is fine" rather than leaving a client to guess.
_SYMMETRIC = {"aes", "aes-hsm", "oct", "oct-hsm", "hmac", "chacha20"}

# Signing and wrapping run on different clocks; see the module docstring.
_SIGN_OPS = {"sign", "verify"}
_WRAP_OPS = {"wrapkey", "unwrapkey", "encrypt", "decrypt", "wrap_key", "unwrap_key"}


def classify(family: str | None) -> bool | None:
    """True vulnerable, False not vulnerable, None unknown. Never a guess."""
    if not family:
        return None
    f = str(family).strip().lower()
    if f in _VULNERABLE:
        return True
    if f in _QUANTUM_SAFE or f in _SYMMETRIC:
        return False
    return None


def purpose(operations: object) -> str:
    """`sign`, `wrap`, `both` or `unknown`, from declared key operations."""
    if not isinstance(operations, (list, tuple, set)):
        return "unknown"
    ops = {str(o).strip().lower().replace("-", "") for o in operations}
    signing = bool(ops & {o.replace("_", "") for o in _SIGN_OPS})
    wrapping = bool(ops & {o.replace("_", "") for o in _WRAP_OPS})
    if signing and wrapping:
        return "both"
    if signing:
        return "sign"
    if wrapping:
        return "wrap"
    return "unknown"


def _expiry(record: dict) -> dt.date | None:
    for key in ("expires", "expiry", "not_after", "expiration_date", "exp"):
        value = record.get(key)
        if not value:
            continue
        try:
            if isinstance(value, (int, float)):
                return dt.datetime.fromtimestamp(value, dt.UTC).date()
            return dt.datetime.fromisoformat(
                str(value).replace("Z", "+00:00")).date()
        except (ValueError, OSError, OverflowError):
            continue
    return None


def _has_rotation_policy(record: dict) -> bool | None:
    for key in ("rotation_policy", "rotationPolicy", "auto_rotate",
                "rotation_period", "next_rotation_time"):
        if key in record:
            return bool(record[key])
    return None


def summarise(records: list[dict], sector: str,
              milestone: dt.date | None = None) -> dict:
    """Counts per sector. Identifiers are read for nothing and written nowhere."""
    milestone = milestone or load_milestone()
    counts: Counter = Counter()
    by_family: Counter = Counter()
    by_purpose: Counter = Counter()

    for record in records:
        family = (record.get("kty") or record.get("key_type")
                  or record.get("algorithm") or record.get("keySpec"))
        vulnerable = classify(family)
        use = purpose(record.get("key_ops") or record.get("operations")
                      or record.get("keyUsage"))
        by_family[str(family or "unknown").lower()] += 1
        by_purpose[use] += 1
        counts[f"quantum_vulnerable_{ {True: 'true', False: 'false', None: 'unknown'}[vulnerable] }"] += 1

        if vulnerable is True:
            counts[f"vulnerable_purpose_{use}"] += 1

        expires = _expiry(record)
        if expires is None:
            # The strongest available at-rest finding, and it needs no new
            # observation: a key with no expiry is a key nobody planned to
            # rotate, which makes it a key nobody planned to migrate. That is a
            # statement about crypto-agility rather than about cryptography,
            # which is the thesis of this whole project.
            counts["no_expiry_set"] += 1
        elif expires > milestone:
            counts["outlives_milestone"] += 1
        else:
            counts["expires_before_milestone"] += 1

        rotation = _has_rotation_policy(record)
        counts[f"rotation_policy_{ {True: 'present', False: 'absent', None: 'unknown'}[rotation] }"] += 1

        if record.get("hsm") or record.get("hsm_backed") or \
                str(family or "").lower().endswith("-hsm"):
            counts["hsm_backed"] += 1

    return {
        "sector": sector,
        "keys_observed": len(records),
        "counts": dict(counts),
        "key_families": dict(by_family),
        "purposes": dict(by_purpose),
        "milestone": milestone.isoformat(),
    }


def run(export: Path, sector: str, out: Path,
        milestone: dt.date | None = None) -> dict:
    raw = json.loads(Path(export).read_text(encoding="utf-8"))
    records = raw if isinstance(raw, list) else (
        raw.get("data") or raw.get("keys") or raw.get("Keys") or [])
    if not isinstance(records, list):
        raise ValueError("export must be a list of key records, or an object "
                         "with a 'data', 'keys' or 'Keys' array")

    payload = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "modality": "E_key_inventory_reported",
        "provenance": "reported",
        "provenance_note": "each record is parsed here so its fields are "
                           "measured; that the export is the key estate is the "
                           "operator's claim",
        "scope_note": "asymmetric key material only. Symmetric keys are counted "
                      "and excluded from migration scope: AES-256 retains 128 "
                      "bits against Grover and needs no replacement",
        "sectors": {validate_sector(sector):
                    summarise(records, validate_sector(sector), milestone)},
        "disclosure_policy": {
            "granularity": "counts",
            "note": "key identifiers, vault names and key ring paths are never "
                    "written; they are not needed to answer the question",
        },
    }
    assert_no_host_identifiers(payload)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Summarise an operator-supplied key management export")
    p.add_argument("--export", type=Path, required=True,
                   help="JSON from ARG, aws kms describe-key, or GCP KMS list")
    p.add_argument("--sector", required=True)
    p.add_argument("--milestone", type=dt.date.fromisoformat, default=None)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
    if not args.export.is_file():
        log.error("export not found: %s", args.export)
        return 2

    payload = run(args.export, args.sector, args.out, args.milestone)
    s = next(iter(payload["sectors"].values()))
    c = s["counts"]
    log.info("%d keys; vulnerable %d, unknown family %d",
             s["keys_observed"], c.get("quantum_vulnerable_true", 0),
             c.get("quantum_vulnerable_unknown", 0))
    if c.get("no_expiry_set"):
        log.warning("%d keys have no expiry set: nobody has planned to rotate "
                    "them, so nobody has planned to migrate them",
                    c["no_expiry_set"])
    log.info("written: %s", args.out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
