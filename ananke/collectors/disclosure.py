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

import ipaddress
import re
import subprocess
from functools import lru_cache
from pathlib import Path, PurePosixPath
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
#
# The boundaries are hand-written rather than `\b`, and the reason is a defect
# this module shipped with. `_` is a word character, so `\b` never fires
# between `_` and a letter, and a match can only begin at a word boundary:
# `acme_bank.pl` produced no match at all and walked through both guards. The
# leading lookbehind blocks continuation of an alphanumeric run (`xxbank.pl`)
# and of a longer dotted name (`a.bank.pl`, already covered by the full match)
# while treating `_` as a delimiter, which is what it is in practice. The
# trailing lookahead is deliberately weaker than `\b`: a host glued to a
# suffix (`bank.pl_backup`) is still host identity and must be caught.
HOSTNAME_RE = re.compile(
    r"(?<![a-z0-9.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}"
    r"[a-z]{2,24}(?![a-z0-9-])",
    re.IGNORECASE,
)

# IPv4 literals. HOSTNAME_RE cannot match them - its final label must be
# alphabetic - so without this pattern a dotted quad walks straight through
# the guard, and an IP is host identity as surely as a hostname is. Octets are
# range-checked to 0-255 so that four-part version strings with a large
# component (e.g. 3.5.0.2024) do not false-positive; the residual collision
# (a version that is also a valid quad, like 1.1.1.1) is accepted as the cost
# of a guard that is deliberately blunt.
#
# Boundaries hand-written for the same reason as HOSTNAME_RE: `\b` made
# `host_10.0.0.1` invisible. The leading lookbehind still refuses to start
# mid-number or mid-dotted-run, so `3.5.0.2024` does not match on a shifted
# window.
IPV4_RE = re.compile(
    r"(?<![0-9.])(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?![0-9])"
)

# IPv6, closing T14. Neither host pattern nor IPV4_RE matches a colon-separated
# address, so a bare or bracketed literal walked through both guards until now.
#
# Regex alone is the wrong tool here: an expression loose enough to catch every
# valid form also catches clock times, MAC addresses and C++ scope resolution,
# and one tight enough to avoid them misses compressed forms. So the pattern
# only nominates candidates and `ipaddress` decides. That is exact by
# construction: `12:34:56` is not a valid address and is rejected without any
# heuristic about what a time looks like.
#
# The lookarounds stop a candidate starting mid-token, which is what keeps
# `std::vector` out: `s` is not a hex digit, and `d::` cannot start because the
# preceding character is a letter.
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9a-z:.])\[?([0-9a-f:]{2,45}(?:%[0-9a-z_.-]{1,32})?)\]?(?![0-9a-z:.])",
    re.IGNORECASE,
)

# Addresses that identify nobody. The unspecified address and loopback appear in
# configuration and documentation constantly, and flagging them would train
# people to disable the guard - the one outcome worse than a narrow exemption.
_IPV6_IDENTIFIES_NOBODY = {"::", "::1"}


def find_ipv6(text: str) -> list[str]:
    """Return IPv6 literals in `text`, validated rather than pattern-guessed."""
    found = []
    for candidate in _IPV6_CANDIDATE_RE.findall(text):
        addr = candidate.split("%", 1)[0]
        if ":" not in addr:
            continue
        try:
            parsed = ipaddress.IPv6Address(addr)
        except ValueError:
            continue
        if str(parsed) in _IPV6_IDENTIFIES_NOBODY:
            continue
        found.append(candidate)
    return found


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

# Strings that legitimately look like hostnames in structured output: source
# attribution, standards references, artefact names the writers emit.
#
# This set is the allowlist for the *strict* guard and is deliberately small
# and hand-maintained. It must contain only tokens HOSTNAME_RE can actually
# produce; an entry the regex never yields is dead weight that reads as
# coverage (`tests/test_sprint8.py` fails the build on one).
#
# Repository filenames are no longer listed here. They are derived from the
# tracked file list at scan time and apply to the prose scan only - see
# `_repo_file_tokens`.
ALLOWED_TOKENS = {t.lower() for t in {
    "crt.sh", "sectors.json", "weights.yaml", "targets.yaml", "report.md",
}}

# Extensions eligible for the derived repository-file allowlist. This is
# SAFE_FILE_EXTENSIONS plus the two live-ccTLD extensions the repo actually
# uses in prose. They are admitted here, and only here, because membership is
# additionally conditioned on the name being a file tracked in this repository
# - which `.md` alone never was.
_REPO_FILE_EXTENSIONS = SAFE_FILE_EXTENSIONS | {".md", ".py"}

# Directories never consulted when deriving repository filenames. `data/`
# holds the raw store; a filename there can be host-derived and must not be
# able to allowlist itself.
_UNTRACKED_SCAN_SKIP = {
    ".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "data", ".eggs",
}

# Hosts that belong to the repository's own publishing infrastructure rather
# than to any estate under assessment. A CI badge is a URL to the forge, and a
# guard that fails the build over its own badge gets switched off.
#
# Prose only, and separate from ALLOWED_TOKENS on purpose. `github.com` in a
# collected record is a host identifier like any other and must still fail the
# structural guard; `github.com` in README is where this repository lives.
_PROSE_INFRASTRUCTURE = frozenset({
    "github.com", "raw.githubusercontent.com", "badge.svg", "shields.io",
})

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _looks_like_this_repo(base: Path) -> bool:
    """Sentinel for the filesystem fallback.

    `_REPO_ROOT` is derived from `__file__`, so for a wheel installed into
    site-packages it points at site-packages. Walking that would be slow and,
    worse, would allowlist filenames from unrelated third-party packages. The
    fallback exists for a source checkout or tarball, so it only runs where the
    project's own marker files are present. Anywhere else, no derived allowlist.
    """
    return (base / "pyproject.toml").is_file() and (base / "ananke").is_dir()


@lru_cache(maxsize=4)
def _repo_file_tokens(root: str | None = None) -> frozenset[str]:
    """Host-like tokens that are really filenames tracked in this repository.

    The hand-maintained allowlist was a maintenance trap: a new repo file with
    a live-ccTLD extension (`.md` is Moldova) turned main red at the next
    commit, and the fix was always to append one more literal. This derives
    the same information from the file list instead.

    Two-stage lookup, git first: `git ls-files` is authoritative because a
    tracked path is one a human committed. The filesystem walk is a fallback
    for a source tarball or an installed package with no `.git`, and it is
    scoped by `_UNTRACKED_SCAN_SKIP` so nothing under `data/` can whitelist
    itself. Both stages fail closed to an empty set: no allowlist is strictly
    safer than a wrong one.

    Tokens are the basename *and* whatever HOSTNAME_RE extracts from it, since
    the regex tokenises `hndl_score.py` as `score.py` and the scan only ever
    sees the extracted form.
    """
    base = Path(root) if root else _REPO_ROOT
    names: set[str] = set()
    try:
        out = subprocess.run(
            ["git", "-C", str(base), "ls-files", "-z"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout
        names = {PurePosixPath(p).name for p in out.split("\0") if p}
    except (OSError, subprocess.SubprocessError):
        names = set()

    if not names and _looks_like_this_repo(base):
        try:
            for path in base.rglob("*"):
                if not path.is_file():
                    continue
                if _UNTRACKED_SCAN_SKIP & set(path.relative_to(base).parts[:-1]):
                    continue
                names.add(path.name)
        except OSError:
            return frozenset()

    tokens: set[str] = set()
    for name in names:
        lowered = name.lower()
        if not any(lowered.endswith(ext) for ext in _REPO_FILE_EXTENSIONS):
            continue
        tokens.add(lowered)
        tokens.update(m.lower() for m in HOSTNAME_RE.findall(lowered))
    return frozenset(tokens)


class DisclosureViolation(AssertionError):
    """Raised instead of writing something that breaks the scope statement."""


def _is_allowed(
    token: str,
    extra_allowed: set[str] | None = None,
    repo_files: bool = False,
) -> bool:
    """Decide whether a host-shaped token is benign.

    `repo_files` admits the derived repository-filename tokens and defaults to
    off. `assert_no_host_identifiers` must never turn it on: collected data
    lands in structured output, and a filename-shaped exemption there is
    exactly the blind spot the extension policy above refuses to create.
    """
    t = token.lower()
    if t in ALLOWED_TOKENS:
        return True
    if extra_allowed and t in {e.lower() for e in extra_allowed}:
        return True
    if any(t.endswith(ext) for ext in SAFE_FILE_EXTENSIONS):
        return True
    if repo_files and t in _repo_file_tokens():
        return True
    if repo_files and t in _PROSE_INFRASTRUCTURE:
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
    elif isinstance(payload, (bytes, bytearray)):
        # X.509 name attributes are `str | bytes`: `cryptography` hands back
        # bytes when the attribute uses an encoding it will not decode. Until
        # sprint 14 the walk inspected `str` only, so a subject encoded that way
        # carried host identity through the guard untouched. Found by mypy, on
        # a return type that did not match its declaration - which is the whole
        # argument for running a type checker on a codebase whose failures are
        # silent rather than loud.
        assert_no_host_identifiers(
            bytes(payload).decode("utf-8", errors="replace"), path)
    elif isinstance(payload, str):
        for match in HOSTNAME_RE.findall(payload):
            if not _is_allowed(match):
                raise DisclosureViolation(
                    f"{path}: string looks like a hostname: {match!r}"
                )
        for match in find_ipv6(payload):
            raise DisclosureViolation(
                f"IPv6 literal in a committed payload: {match!r}")
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
    found = [
        m for m in HOSTNAME_RE.findall(text)
        if not _is_allowed(m, extra_allowed, repo_files=True)
    ]
    found += find_ipv6(text)
    found += [m for m in IPV4_RE.findall(text)
              if not (extra_allowed and m in extra_allowed)]
    return found
