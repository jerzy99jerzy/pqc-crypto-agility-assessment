"""Disclosure guard.

The scope statement says no organisation is ever named next to a vulnerability
finding, and that host-level data never leaves the local raw store. That rule
is worth exactly as much as its enforcement. This module is the enforcement:
anything written to data/aggregates/ or docs/ passes through it first.

Two checks:

  assert_no_host_identifiers  structural. Walks a payload and rejects strings
                              that look like hostnames, plus any key known to
                              carry host identity. Deliberately blunt: false
                              positives here cost a rename, false negatives
                              cost the premise of the project.

  assert_bucket_sizes         statistical. Rejects sector buckets below the
                              declared minimum, because a bucket of one is a
                              named organisation wearing a sector label.
"""

from __future__ import annotations

import re
from typing import Any

# Keys that carry host identity in the raw store and must never reach an
# aggregate. Checked by name, independent of the value.
FORBIDDEN_KEYS = {
    "host", "hosts", "subject_cn", "san_dns", "server_name",
    "domain", "domains", "crtsh_id", "sha256", "serial_number",
    # endpoint inventory exports carry their own identity columns
    "device", "deviceid", "device_id", "devicename", "device_name",
    "computer", "computername", "hostname", "fqdn", "ip", "ipaddress",
}

# Matches a dotted label sequence ending in a plausible TLD. Intentionally
# greedy about what counts as a hostname.
HOSTNAME_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}[a-z]{2,24}\b", re.IGNORECASE
)

# IPv4 literals. HOSTNAME_RE cannot match them - its final label must be
# alphabetic - so without this pattern a dotted quad walks straight through
# the guard, and an IP is host identity as surely as a hostname is. Octets are
# range-checked to 0-255 so that four-part version strings with a large
# component (e.g. 3.5.0.2024) do not false-positive; the residual collision
# (a version that is also a valid quad, like 1.1.1.1) is accepted as the cost
# of a guard that is deliberately blunt.
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

# File extensions that cannot be confused with a top-level domain, so a token
# ending in one is a filename rather than a host.
#
# Note what is deliberately absent: .sh, .py, .md, .ai, .io, .cd, .tv are all
# live ccTLDs. Allowing them by extension would create a blind spot exactly
# where a domain is most likely to be mistaken for a filename, so repository
# files with those extensions are listed explicitly below instead.
SAFE_FILE_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".csv", ".tsv", ".txt", ".kql", ".pem",
    ".der", ".log", ".xlsx", ".conf", ".cfg", ".toml", ".ini", ".sql",
}

# Strings that legitimately look like hostnames in aggregate output: source
# attribution, standards references, algorithm identifiers.
ALLOWED_TOKENS = {
    "crt.sh", "sectors.json", "handshake_demo.json", "weights.yaml",
    "hndl_sector_scores.json", "targets.yaml", "reference_hosts.yaml",
    "selection_manifest.json", "methodology.md", "README.md", "report.md",
    "passive_cert.py", "hndl_score.py", "certparse.py", "store.py",
    "crtsh.py", "disclosure.py", "select_targets.py", "build_report.py",
}


class DisclosureViolation(AssertionError):
    """Raised instead of writing something that breaks the scope statement."""


def _is_allowed(token: str, extra_allowed: set[str] | None = None) -> bool:
    t = token.lower()
    if t in ALLOWED_TOKENS:
        return True
    if extra_allowed and t in {e.lower() for e in extra_allowed}:
        return True
    if any(t.endswith(ext) for ext in SAFE_FILE_EXTENSIONS):
        return True
    # Version strings such as 3.5.0 and OpenSSL 3.0.13 are not hostnames.
    return all(part.isdigit() for part in t.split("."))


def assert_no_host_identifiers(payload: Any, path: str = "$") -> None:
    """Recursively reject host identity in a structure destined for disclosure."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            if str(key).lower() in FORBIDDEN_KEYS:
                raise DisclosureViolation(
                    f"{path}.{key}: key carries host identity and must not appear "
                    "in disclosed output"
                )
            assert_no_host_identifiers(value, f"{path}.{key}")
    elif isinstance(payload, (list, tuple)):
        for i, value in enumerate(payload):
            assert_no_host_identifiers(value, f"{path}[{i}]")
    elif isinstance(payload, str):
        for match in HOSTNAME_RE.findall(payload):
            if not _is_allowed(match):
                raise DisclosureViolation(
                    f"{path}: string looks like a hostname: {match!r}"
                )
        for match in IPV4_RE.findall(payload):
            raise DisclosureViolation(
                f"{path}: string contains an IPv4 literal: {match!r}"
            )


def assert_bucket_sizes(buckets: dict[str, int], minimum: int) -> None:
    """Reject any emitted sector bucket smaller than the declared minimum."""
    too_small = {k: v for k, v in buckets.items() if v < minimum}
    if too_small:
        raise DisclosureViolation(
            f"sector buckets below min_bucket_size={minimum}: {too_small}. "
            "Suppress them before writing, do not report n=1 as a sector."
        )


CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
CODE_SPAN_RE = re.compile(r"`[^`\n]+`")


def scan_text(
    text: str, extra_allowed: set[str] | None = None, strip_code: bool = True
) -> list[str]:
    """Non-raising variant for prose. Returns suspected hostnames.

    extra_allowed exists for one legitimate case: hosts declared in
    config/reference_hosts.yaml under `self` or `reference` may be named,
    because naming them is part of the method statement. Nothing from the
    third-party target list is ever eligible.

    strip_code removes fenced blocks and inline code spans before matching.
    Without it, every dotted identifier in the documentation (os.replace,
    cfg.weights, ssl.log) is a false positive, and a guard that cries wolf on
    every commit gets switched off within a week. The accepted trade-off: a
    hostname hidden inside backticks in a markdown file would not be caught by
    the prose scan. Structural JSON output is scanned with the strict guard,
    which has no such exemption, and that is where collected data actually
    lands.
    """
    if strip_code:
        text = CODE_SPAN_RE.sub(" ", CODE_FENCE_RE.sub(" ", text))
    found = [m for m in HOSTNAME_RE.findall(text) if not _is_allowed(m, extra_allowed)]
    found += [m for m in IPV4_RE.findall(text)
              if not (extra_allowed and m in extra_allowed)]
    return found
