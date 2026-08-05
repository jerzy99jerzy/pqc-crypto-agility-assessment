"""Certificate Transparency client (crt.sh).

Passive only: CT logs are a public append-only record. Querying them generates
zero traffic toward the domain owner's infrastructure.

Two API surfaces are used:
  1. /?q=<domain>&output=json  -> log entry metadata (id, names, validity, issuer)
  2. /?d=<crtsh_id>            -> the certificate itself, PEM

Surface (1) does NOT expose key algorithm or signature algorithm. Those
dimensions require fetching and parsing the certificate from surface (2).
This is the single most common shortcut in "PQC readiness" write-ups: reporting
issuer/expiry from CT metadata and implying the key algorithm was measured.

Operational notes:
  - crt.sh is a free community service and returns 502/504 under load.
    Default rate is deliberately low; be a good citizen or run your own CT
    log-tailer.
  - Only leaf certificates matching the queried name are retained.
"""

from __future__ import annotations

import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

log = logging.getLogger(__name__)

USER_AGENT = (
    "pqc-crypto-agility-assessment/0.1 "
    "(passive CT collection; contact via repository issues)"
)
RETRY_STATUS = {429, 500, 502, 503, 504}


@dataclass
class RateLimiter:
    """Minimum-interval limiter with jitter. Deliberately simple: single process.

    `_last` starts as None rather than 0.0. With 0.0 the first call computes its
    elapsed time against the epoch of time.monotonic(), which on Linux is system
    uptime: large in practice, so the spurious initial sleep never shows up in
    normal runs and only appears when monotonic() happens to start small. That is
    the kind of defect that survives forever because the environment hides it.
    """

    min_interval: float = 2.0
    jitter: float = 0.4
    _last: float | None = None

    def wait(self) -> None:
        if self._last is None:
            self._last = time.monotonic()
            return
        sleep_for = self.min_interval - (time.monotonic() - self._last)
        if sleep_for > 0:
            time.sleep(sleep_for + random.uniform(0, self.jitter))
        self._last = time.monotonic()


class CrtShClient:
    BASE = "https://crt.sh/"

    def __init__(
        self,
        rate: RateLimiter | None = None,
        timeout: int = 45,
        max_retries: int = 4,
    ) -> None:
        self.rate = rate or RateLimiter()
        self.timeout = timeout
        self.max_retries = max_retries

    def _get(self, url: str) -> bytes:
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            self.rate.wait()
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.read()
            except urllib.error.HTTPError as exc:
                last_exc = exc
                if exc.code not in RETRY_STATUS:
                    raise
            except (urllib.error.URLError, TimeoutError) as exc:
                last_exc = exc
            backoff = (2**attempt) + random.uniform(0, 1)
            log.warning("crt.sh retry %d/%d in %.1fs (%s)",
                        attempt + 1, self.max_retries, backoff, last_exc)
            time.sleep(backoff)
        raise RuntimeError(f"crt.sh unreachable after {self.max_retries} attempts: {last_exc}")

    def search(self, domain: str, exclude_expired: bool = True) -> list[dict]:
        """Return CT log entry metadata for a domain (identity match, not wildcard sweep)."""
        import json

        params = {"q": domain, "output": "json"}
        if exclude_expired:
            params["exclude"] = "expired"
        url = self.BASE + "?" + urllib.parse.urlencode(params)
        raw = self._get(url)
        if not raw.strip():
            return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            log.warning("crt.sh returned non-JSON for %s (len=%d)", domain, len(raw))
            return []

    def fetch_certificate(self, crtsh_id: int) -> bytes:
        """Fetch a single certificate as PEM by crt.sh internal id."""
        return self._get(f"{self.BASE}?d={crtsh_id}")


def select_current_leaves(entries: list[dict], limit: int = 3) -> list[dict]:
    """Pick the most recently logged entries, deduplicated by serial number.

    Rationale: a host typically has several overlapping valid certs (renewals,
    multiple CDN edges). Parsing every historical entry burns the upstream API
    for no additional signal on *current* posture.
    """
    seen: set[str] = set()
    out: list[dict] = []
    for e in sorted(entries, key=lambda x: x.get("entry_timestamp") or "", reverse=True):
        serial = str(e.get("serial_number") or e.get("id"))
        if serial in seen:
            continue
        seen.add(serial)
        out.append(e)
        if len(out) >= limit:
            break
    return out
