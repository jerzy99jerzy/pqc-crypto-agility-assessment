"""Certificate sources, and the regime each one implies.

Until sprint 9 the collector was welded to Certificate Transparency. That was
honest while the only estate in scope belonged to third parties, but it made a
first-party engagement impossible: an operator who hands over a directory of
their own certificates had nowhere to put it.

A source is not only a way of getting bytes. It carries the regime the rest of
the pipeline has to respect, and the three attributes below are load-bearing:

`provenance`
    `measured` for Certificate Transparency: the log is an independent public
    record and nobody in the transaction chose what it contains. `reported` for
    an operator-supplied dump: each individual certificate is still parsed by us
    and its fields are measured, but the *completeness* of the set is a claim by
    the party paying for the report. Those are different epistemic objects and
    the output says which one produced it.

`modality`
    Carried into the aggregate and checked at aggregation time. Records from
    different modalities are never mixed into one set of counts, because
    "40% RSA" means something different across a public sample than across one
    operator's declared estate.

`first_party`
    Whether the estate belongs to the party the report is for. This is the only
    thing that may relax minimum bucket size, and only a source may assert it -
    never a command-line flag on its own. See `passive_cert.aggregate`.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

try:
    from collectors.certparse import parse_certificate
    from collectors.crtsh import CrtShClient, select_current_leaves
except ImportError:  # pragma: no cover
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from collectors.certparse import parse_certificate
    from collectors.crtsh import CrtShClient, select_current_leaves

log = logging.getLogger("sources")

# Extensions read by the offline source. DER and PEM are both handled by
# `parse_certificate`, which sniffs the encoding and never raises.
PEM_SUFFIXES = {".pem", ".crt", ".cer", ".der"}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


@runtime_checkable
class CertificateSource(Protocol):
    """What the collector needs from any source of certificates."""

    name: str
    provenance: str
    modality: str
    first_party: bool

    def iter_records(self) -> Iterator[dict]:
        """Yield one host-level record per host, in store format."""
        ...


class CrtShSource:
    """Third-party estate through Certificate Transparency. Modality A.

    Sends no packet to any target host. The only network peer is crt.sh.
    """

    name = "crt.sh"
    provenance = "measured"
    modality = "passive"
    first_party = False

    def __init__(
        self,
        targets: dict[str, list[str]],
        client: CrtShClient,
        leaves: int = 2,
        skip: object = None,
    ) -> None:
        self.targets = targets
        self.client = client
        self.leaves = leaves
        # Callable taking a host and returning True when a fresh record exists.
        self.skip = skip

    def iter_records(self) -> Iterator[dict]:
        total = sum(len(v) for v in self.targets.values())
        done = 0
        for sector, hosts in self.targets.items():
            for host in hosts:
                done += 1
                if self.skip is not None and self.skip(host):
                    log.info("[%d/%d] %s: fresh, skipping", done, total, host)
                    continue
                log.info("[%d/%d] %s (%s)", done, total, host, sector)
                yield self._collect_host(host, sector)

    def _collect_host(self, host: str, sector: str) -> dict:
        record = {
            "host": host,
            "sector": sector,
            "collected_at": _now(),
            "source": self.name,
            "provenance": self.provenance,
            "modality": self.modality,
            "certificates": [],
            "errors": [],
        }
        try:
            entries = self.client.search(host)
        except Exception as exc:
            record["errors"].append(f"search: {exc}")
            return record

        for entry in select_current_leaves(entries, limit=self.leaves):
            cid = entry.get("id")
            if cid is None:
                continue
            try:
                pem = self.client.fetch_certificate(int(cid))
            except Exception as exc:
                record["errors"].append(f"fetch {cid}: {exc}")
                continue
            d = parse_certificate(pem).to_dict()
            d["crtsh_id"] = cid
            d["ct_entry_timestamp"] = entry.get("entry_timestamp")
            record["certificates"].append(d)
        return record


class LocalPemSource:
    """An operator's own certificates, read from a directory. Offline.

    No network peer at all: the pipeline never learns that these hosts exist
    from anywhere except the files handed to it.

    Host identity is taken from the certificate subject, not from the filename.
    A filename is a label someone typed; the subject is part of the signed
    object. Where a certificate carries no usable subject the record is keyed by
    file stem and says so, rather than silently inventing a host.

    Sector assignment is supplied by the caller, because a single operator's
    estate is one sector by construction and there is nothing in a certificate
    that reveals which.
    """

    name = "local-pem"
    provenance = "reported"
    modality = "first_party_offline"
    first_party = True

    def __init__(self, directory: Path, sector: str) -> None:
        self.directory = Path(directory)
        self.sector = sector

    def iter_records(self) -> Iterator[dict]:
        files = sorted(
            p for p in self.directory.rglob("*")
            if p.is_file() and p.suffix.lower() in PEM_SUFFIXES
        )
        if not files:
            log.warning("no certificate files under %s", self.directory)
        by_host: dict[str, dict] = {}
        for path in files:
            try:
                raw = path.read_bytes()
            except OSError as exc:
                log.warning("unreadable: %s (%s)", path.name, exc)
                continue
            parsed = parse_certificate(raw)
            d = parsed.to_dict()
            host = self._host_for(d, path)
            record = by_host.setdefault(host, {
                "host": host,
                "sector": self.sector,
                "collected_at": _now(),
                "source": self.name,
                "provenance": self.provenance,
                "modality": self.modality,
                "certificates": [],
                "errors": [],
            })
            # The filename is recorded for traceability back to the client's
            # dump, and is never used as evidence about the certificate.
            d["source_file"] = path.name
            record["certificates"].append(d)
        for host in sorted(by_host):
            yield by_host[host]

    @staticmethod
    def _host_for(cert: dict, path: Path) -> str:
        cn = cert.get("subject_cn")
        if isinstance(cn, str) and cn.strip():
            return cn.strip().lstrip("*.").lower()
        for value in cert.get("san_dns") or []:
            if isinstance(value, str) and value.strip():
                return value.strip().lstrip("*.").lower()
        return f"unidentified-{path.stem.lower()}"
