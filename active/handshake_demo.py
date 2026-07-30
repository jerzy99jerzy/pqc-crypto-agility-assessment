#!/usr/bin/env python3
"""Active PQC handshake probe (Modality B) - own and reference infrastructure only.

What it does: one TLS 1.3 handshake per target, offering the hybrid group
X25519MLKEM768 (IANA 0x11EC, RFC 9794 naming), then reads back which group the
server actually negotiated.

What it is not: a scanner. There is no port enumeration, no target discovery,
no rate-multiplied sweep. Targets must be declared in an allowlist file with an
explicit ownership category; anything else is refused before a socket is opened.

Allowlist categories:
    self       - infrastructure the operator owns and is authorised to test
    reference  - public implementations documented as PQC-enabled that serve
                 billions of connections (positive controls for the method)

Requires OpenSSL >= 3.5, where X25519MLKEM768 is available and is a default
group. Older OpenSSL cannot offer the group and the probe will refuse to run
rather than emit a false "no PQC support" result - the most likely failure mode
of this class of test is misattributing a *client* limitation to the server.

Usage:
    python active/handshake_demo.py --allowlist config/reference_hosts.yaml
    python active/handshake_demo.py --host www.example.com --allowlist ...
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
from collectors.store import write_json_atomic  # noqa: E402

log = logging.getLogger("handshake_demo")

HYBRID_GROUP = "X25519MLKEM768"
MIN_OPENSSL = (3, 5, 0)

# RFC 8446 section 4.1.3: the HelloRetryRequest special ServerHello.random value.
HRR_RANDOM_PREFIX = "CF 21 AD 74 E5 9A 61 11"

RE_VERSION = re.compile(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)")
RE_NEGOTIATED_GROUP = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)")
RE_PROTOCOL = re.compile(r"Protocol\s*:\s*(\S+)")
RE_CIPHER = re.compile(r"Cipher\s*:\s*(\S+)")
RE_SERVER_TEMP_KEY = re.compile(r"Server Temp Key:\s*(.+)")


class PreflightError(RuntimeError):
    pass


def openssl_version(binary: str) -> tuple[int, int, int]:
    if shutil.which(binary) is None:
        raise PreflightError(f"openssl binary not found: {binary}")
    out = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=15).stdout
    m = RE_VERSION.search(out)
    if not m:
        raise PreflightError(f"cannot parse openssl version from: {out.strip()!r}")
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def preflight(binary: str) -> dict:
    """Fail loudly if the client cannot offer the hybrid group."""
    ver = openssl_version(binary)
    if ver < MIN_OPENSSL:
        raise PreflightError(
            f"OpenSSL {'.'.join(map(str, ver))} cannot offer {HYBRID_GROUP}; "
            f">= {'.'.join(map(str, MIN_OPENSSL))} required. Refusing to run: a negative "
            "result here would measure the client, not the server."
        )
    groups_ok = None
    try:
        listing = subprocess.run(
            [binary, "list", "-tls-groups"], capture_output=True, text=True, timeout=15
        )
        if listing.returncode == 0 and listing.stdout.strip():
            groups_ok = HYBRID_GROUP.lower() in listing.stdout.lower()
    except (subprocess.SubprocessError, OSError):
        groups_ok = None  # older syntax; version gate above is the binding check
    if groups_ok is False:
        raise PreflightError(f"{HYBRID_GROUP} not present in `openssl list -tls-groups`")
    return {
        "openssl_version": ".".join(map(str, ver)),
        "group_listed": groups_ok,
        "provenance": "measured",
    }


def load_allowlist(path: Path) -> dict[str, str]:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    allowed: dict[str, str] = {}
    for category in ("self", "reference"):
        for host in doc.get(category) or []:
            allowed[str(host).strip().lower()] = category
    if not allowed:
        raise PreflightError(f"allowlist {path} declares no hosts under 'self' or 'reference'")
    return allowed


def parse_handshake_output(
    blob: str, host: str, port: int, groups: str, returncode: int, started_iso: str
) -> dict:
    """Turn raw s_client output into a record. Pure function, no I/O.

    Split out from probe() so it can be tested against captured transcripts
    without an OpenSSL 3.5 client, which is not available in any environment
    used to build this. The success path of the probe is otherwise untestable
    here, and an untested parser that only ever sees failure output is a parser
    that will misread the one result that matters.
    """
    negotiated = RE_NEGOTIATED_GROUP.search(blob)
    # HelloRetryRequest heuristic: with an HRR the client writes ClientHello twice.
    client_hellos = len(re.findall(r"write client hello", blob, flags=re.I))

    record = {
        "host": host,
        "port": port,
        "probed_at": started_iso,
        "modality": "B_active_self_and_reference",
        "offered_groups": groups,
        "openssl_returncode": returncode,
        "negotiated_group": negotiated.group(1) if negotiated else None,
        "protocol": (m.group(1) if (m := RE_PROTOCOL.search(blob)) else None),
        "cipher": (m.group(1) if (m := RE_CIPHER.search(blob)) else None),
        "server_temp_key": (m.group(1).strip() if (m := RE_SERVER_TEMP_KEY.search(blob)) else None),
        "hello_retry_request_inferred": client_hellos > 1,
        "client_hello_count": client_hellos,
        "provenance": "measured",
        "interpretation_provenance": "inference",
    }
    record["pqc_hybrid_negotiated"] = (
        record["negotiated_group"] is not None
        and "mlkem" in record["negotiated_group"].lower().replace("-", "")
    )
    if returncode != 0 and record["negotiated_group"] is None:
        record["error"] = "handshake did not complete; see openssl_returncode"
    return record


def probe(host: str, port: int, binary: str, timeout: int, groups: str) -> tuple[dict, str]:
    """One handshake. Returns (record, raw_transcript); never raises on failure."""
    cmd = [
        binary, "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-groups", groups,
        "-tls1_3",
        "-state",
        "-brief",
    ]
    started = dt.datetime.now(dt.timezone.utc)
    try:
        proc = subprocess.run(
            cmd, input="Q\n", capture_output=True, text=True, timeout=timeout
        )
        blob = proc.stdout + proc.stderr
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        blob, rc = "", -1

    record = parse_handshake_output(blob, host, port, groups, rc, started.isoformat())
    return record, blob


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="PQC hybrid handshake probe (allowlisted targets only)")
    p.add_argument("--allowlist", type=Path, default=REPO_ROOT / "config" / "reference_hosts.yaml")
    p.add_argument("--host", action="append", default=[], help="subset of allowlist to probe")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--groups", default=HYBRID_GROUP)
    p.add_argument("--openssl", default="openssl")
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "aggregates" / "handshake_demo.json")
    p.add_argument("--capture-dir", type=Path, default=None,
                   help="if set, write the raw s_client transcript per host here "
                        "for audit; these are real captures, kept out of aggregates")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )

    # Scope gate first, capability check second. The refusal message for an
    # out-of-scope target must not depend on which OpenSSL happens to be installed.
    try:
        allowed = load_allowlist(args.allowlist)
    except PreflightError as exc:
        log.error("allowlist error: %s", exc)
        return 2

    targets = [h.lower() for h in args.host] if args.host else list(allowed)
    refused = [h for h in targets if h not in allowed]
    if refused:
        log.error("refusing non-allowlisted target(s): %s", ", ".join(refused))
        log.error("add the host to %s under 'self' or 'reference' if you are "
                  "authorised to test it", args.allowlist)
        return 3

    try:
        env = preflight(args.openssl)
    except PreflightError as exc:
        log.error("preflight failed: %s", exc)
        return 2

    results = []
    for host in targets:
        log.info("handshake -> %s (%s)", host, allowed[host])
        rec, transcript = probe(host, args.port, args.openssl, args.timeout, args.groups)
        rec["allowlist_category"] = allowed[host]
        results.append(rec)
        if args.capture_dir:
            args.capture_dir.mkdir(parents=True, exist_ok=True)
            safe = host.replace(":", "_").replace("/", "_")
            (args.capture_dir / f"{safe}.transcript.txt").write_text(transcript, encoding="utf-8")
        log.info(
            "  negotiated=%s hybrid=%s hrr_inferred=%s",
            rec["negotiated_group"], rec["pqc_hybrid_negotiated"],
            rec["hello_retry_request_inferred"],
        )

    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "environment": env,
        "scope_statement": (
            "Targets restricted to operator-owned infrastructure and public reference "
            "implementations. One handshake per target. No third-party estate touched."
        ),
        "results": results,
    }
    write_json_atomic(args.out, payload)
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
