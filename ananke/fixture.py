#!/usr/bin/env python3
"""Synthetic estates, so the offline path runs before any client exists.

Two reasons this is a first-class command rather than a test helper.

The practical one: `--source local-pem` was shipped in v0.9.0 with nothing to
feed it. A reader who clones the repository cannot exercise half the pipeline
without an estate of their own, which is the wrong first impression for a tool
whose entire pitch is that it does not need your production network.

The methodological one, borrowed from the sibling repository `phantomatics`: an
adversarial fixture is worth more than a clean one. The clean world confirms the
parser works, which was never in doubt. The hostile and partial worlds encode
what an operator's dump actually looks like when somebody has an interest in how
the report reads, and they are what the guard and the provenance labels have to
survive. Every certificate here is generated at runtime and self-signed; nothing
in this module is a real indicator of anything.

Usage:
    pqc-fixture --out /tmp/estate --world clean
    pqc-fixture --out /tmp/estate --world partial
    pqc-fixture --out /tmp/estate --world hostile
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID

log = logging.getLogger("fixture")

WORLDS = ("clean", "partial", "hostile")


def _make(cn: str | None, days: int, algorithm: str = "rsa2048",
          sans: list[str] | None = None) -> bytes:
    key: PrivateKeyTypes
    if algorithm == "rsa2048":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sig: Any = hashes.SHA256()
    elif algorithm == "rsa4096":
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        sig = hashes.SHA256()
    elif algorithm == "ec256":
        key = ec.generate_private_key(ec.SECP256R1())
        sig = hashes.SHA256()
    elif algorithm == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
        sig = None
    else:  # pragma: no cover - guarded by argparse choices upstream
        raise ValueError(algorithm)

    now = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn else []
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(attrs))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ANANKE fixture CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=days))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    return builder.sign(key, sig).public_bytes(serialization.Encoding.PEM)


def _clean() -> dict[str, bytes]:
    """An estate as an inventory tool would like to find it.

    A realistic spread: mostly RSA-2048, some EC, one long-lived certificate
    that crosses the 2030 milestone and is the finding the report exists to
    surface.
    """
    return {
        "gateway.operator.example.pem": _make("gateway.operator.example", 90),
        "api.operator.example.pem": _make("api.operator.example", 397, "ec256"),
        "portal.operator.example.pem": _make("portal.operator.example", 365),
        "legacy-edi.operator.example.pem": _make("legacy-edi.operator.example", 2200, "rsa4096"),
        "vpn.operator.example.pem": _make("vpn.operator.example", 730),
        "mail.operator.example.pem": _make("mail.operator.example", 90, "ed25519"),
    }


def _partial() -> dict[str, bytes]:
    """The convenient dump: adversary A3 in `docs/THREAT-MODEL.md`.

    Every certificate here is genuine and nothing in it is false. The estate
    that would have failed is simply not in the directory, and no property of
    the files reveals that. This world exists to make the point that
    completeness is `reported`, never `measured`, and that no amount of parsing
    recovers it.
    """
    return {
        "gateway.operator.example.pem": _make("gateway.operator.example", 90),
        "api.operator.example.pem": _make("api.operator.example", 90, "ec256"),
        "portal.operator.example.pem": _make("portal.operator.example", 90, "ec256"),
    }


def _hostile() -> dict[str, bytes]:
    """A dump assembled by somebody who has read the code.

    Filenames that contradict subjects, host identity glued to an underscore,
    an empty subject, and a file that is not a certificate at all. None of these
    may crash the run, invent a host, or put an identifier into committed
    output.
    """
    return {
        # filename claims one host, the signed subject says another
        "gateway.operator.example.pem": _make("finance-customer.example", 90),
        # underscore adjacency: passed both guards until v0.8.0
        "prefix_bank.example.pem": _make("prefix_bank.example", 400),
        # no subject at all; must not be given an invented host
        "anonymous.pem": _make(None, 120, sans=None),
        # subject empty, identity only in SAN
        "san-only.pem": _make(None, 120, sans=["edge.operator.example"]),
        # not a certificate; the parser must record an error and continue
        "truncated.pem": b"-----BEGIN CERTIFICATE-----\nnot base64 at all\n",
        # long-lived and quantum-vulnerable: the finding that must survive
        "legacy-edi.operator.example.pem": _make("legacy-edi.operator.example", 2200),
    }


BUILDERS = {"clean": _clean, "partial": _partial, "hostile": _hostile}


def build(out: Path, world: str) -> list[Path]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, pem in BUILDERS[world]().items():
        path = out / name
        path.write_bytes(pem)
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate a synthetic certificate estate")
    p.add_argument("--out", type=Path, required=True, help="output directory")
    p.add_argument("--world", choices=WORLDS, default="clean")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )
    written = build(args.out, args.world)
    log.info("%s world: %d files in %s", args.world, len(written), args.out)
    log.info("everything here is generated and self-signed; no real estate is represented")
    log.info("next: pqc-collect --source local-pem --pem-dir %s --sector logistics", args.out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
