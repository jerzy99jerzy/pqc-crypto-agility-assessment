"""Idempotent per-host store with atomic writes.

Design constraints:
  - one file per host, keyed by host, so a rerun is resumable at host granularity
  - write via tmp file + os.replace (atomic on POSIX within the same filesystem)
  - TTL-based freshness so reruns do not re-hit upstream APIs
  - raw store lives under data/raw/ which is git-ignored; only sector-level
    aggregates are ever committed
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

_SAFE = re.compile(r"[^a-z0-9._-]+")


# Filesystem limits are typically 255 bytes per name. A subject CN is capped at
# 64 by X.509, but a SAN dNSName is not, and the offline source derives host
# identity from SAN when the subject is empty - so the key length is
# attacker-chosen. Cap it and keep uniqueness with a digest suffix; a hostile
# estate must not be able to stop a run with one long name (found in the
# sprint 10 review, probe P5).
_MAX_KEY = 120


def host_key(host: str) -> str:
    key = _SAFE.sub("_", host.strip().lower()).strip("_") or "unnamed"
    if len(key) > _MAX_KEY:
        digest = hashlib.sha256(key.encode()).hexdigest()[:12]
        key = f"{key[:_MAX_KEY]}-{digest}"
    return key


class HostStore:
    def __init__(self, root: Path, ttl_seconds: int = 7 * 24 * 3600) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl_seconds

    def path_for(self, host: str) -> Path:
        return self.root / f"{host_key(host)}.json"

    def is_fresh(self, host: str) -> bool:
        p = self.path_for(host)
        if not p.exists():
            return False
        return (time.time() - p.stat().st_mtime) < self.ttl

    def read(self, host: str) -> dict[str, Any] | None:
        p = self.path_for(host)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None  # treat a torn/corrupt file as absent; it will be rewritten

    def write(self, host: str, payload: dict[str, Any]) -> Path:
        p = self.path_for(host)
        fd, tmp = tempfile.mkstemp(dir=str(self.root), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, p)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return p

    def iter_records(self):
        for p in sorted(self.root.glob("*.json")):
            try:
                yield json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue


def write_json_atomic(path: Path, payload: Any) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path
