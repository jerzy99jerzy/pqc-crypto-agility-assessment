"""X.509 dimension extraction.

Scope: turns a DER/PEM certificate into a flat record of *measured* facts.
No risk interpretation happens here - that belongs to scoring/.

Provenance: every field emitted by this module is [measured] unless the key
name carries an explicit `_inference` suffix. There are currently none.

PQC algorithm identifiers per:
  RFC 9881 (ML-DSA in X.509), RFC 9935 (ML-KEM in X.509), NIST CSOR.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, asdict, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)

# --- PQC OID map (NIST CSOR; RFC 9881 / RFC 9935) ---------------------------
PQC_SIG_OIDS: dict[str, str] = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
    "2.16.840.1.101.3.4.3.32": "HashML-DSA-44-SHA512",
    "2.16.840.1.101.3.4.3.33": "HashML-DSA-65-SHA512",
    "2.16.840.1.101.3.4.3.34": "HashML-DSA-87-SHA512",
}

PQC_KEM_OIDS: dict[str, str] = {
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}

# Default milestone anchor; the configured value arrives as a parameter to
# parse_certificate. Kept as a module constant so old imports keep working.
MILESTONE_2030 = dt.date(2030, 12, 31)


@dataclass
class CertRecord:
    """Flat, JSON-serialisable set of measured certificate dimensions."""

    sha256: str
    subject_cn: str | None
    san_dns: list[str] = field(default_factory=list)
    issuer_o: str | None = None
    issuer_cn: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    validity_days: int | None = None
    key_algorithm: str | None = None          # RSA | EC | Ed25519 | ML-KEM-768 | ...
    key_parameter: str | int | None = None    # modulus bits | curve name
    key_quantum_vulnerable: bool | None = None
    signature_algorithm: str | None = None
    signature_oid: str | None = None
    signature_quantum_vulnerable: bool | None = None
    valid_beyond_milestone: bool | None = None
    milestone_date: str | None = None
    parse_error: str | None = None
    provenance: str = "measured"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _key_dimensions(cert: x509.Certificate) -> tuple[str, str | int | None, bool | None]:
    """Return (algorithm, parameter, quantum_vulnerable).

    quantum_vulnerable is tri-state on purpose:
        True   the family is Shor-breakable                       [measured]
        False  the key is a recognised PQC algorithm              [measured]
        None   the algorithm could not be identified              [unknown]

    An unidentified key must resolve to None, never to False. False here reads
    downstream as "measured post-quantum": the aggregator counts it as a PQC
    indicator and the vulnerable-key count silently shrinks. Unknown stays
    unknown; scoring already prices None as 0.5 and the aggregate shows a
    visible "None" bucket instead of quietly inflating PQC adoption.
    """
    spki_oid = cert.public_key_algorithm_oid.dotted_string
    if spki_oid in PQC_KEM_OIDS:
        return PQC_KEM_OIDS[spki_oid], None, False
    if spki_oid in PQC_SIG_OIDS:
        return PQC_SIG_OIDS[spki_oid], None, False

    try:
        pub = cert.public_key()
    except Exception:  # unsupported by the backend and not a known PQC OID
        return f"OID:{spki_oid}", None, None

    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size, True
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.curve.name, True
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size, True
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 255, True
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448, True
    if isinstance(pub, (x25519.X25519PublicKey, x448.X448PublicKey)):
        return type(pub).__name__.replace("PublicKey", ""), None, True
    return f"OID:{spki_oid}", None, None


def _signature_dimensions(cert: x509.Certificate) -> tuple[str, str, bool | None]:
    """Same tri-state contract as _key_dimensions: a signature OID the library
    cannot even name is unknown, not vulnerable. Marking it True would be a
    verdict fabricated from ignorance; None keeps it visible as unverified."""
    oid = cert.signature_algorithm_oid.dotted_string
    if oid in PQC_SIG_OIDS:
        return PQC_SIG_OIDS[oid], oid, False
    name = cert.signature_algorithm_oid._name  # noqa: SLF001 - stable public-ish map
    if name in (None, "Unknown OID"):
        return f"OID:{oid}", oid, None
    return name, oid, True


def _name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return values[0].value if values else None


def parse_certificate(data: bytes, milestone: dt.date | None = None) -> CertRecord:
    """Parse PEM or DER bytes into a CertRecord. Never raises on bad input."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtensionOID, NameOID

    try:
        cert = (
            x509.load_pem_x509_certificate(data)
            if b"-----BEGIN CERTIFICATE-----" in data
            else x509.load_der_x509_certificate(data)
        )
    except Exception as exc:
        return CertRecord(sha256="", subject_cn=None, parse_error=str(exc))

    try:
        san: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        key_alg, key_param, key_vuln = _key_dimensions(cert)
        sig_name, sig_oid, sig_vuln = _signature_dimensions(cert)

        return CertRecord(
            sha256=cert.fingerprint(hashes.SHA256()).hex(),
            subject_cn=_name_attr(cert.subject, NameOID.COMMON_NAME),
            san_dns=sorted(set(san)),
            issuer_o=_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            issuer_cn=_name_attr(cert.issuer, NameOID.COMMON_NAME),
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
            validity_days=(not_after - not_before).days,
            key_algorithm=key_alg,
            key_parameter=key_param,
            key_quantum_vulnerable=key_vuln,
            signature_algorithm=sig_name,
            signature_oid=sig_oid,
            signature_quantum_vulnerable=sig_vuln,
            valid_beyond_milestone=not_after.date() > (milestone or MILESTONE_2030),
            milestone_date=(milestone or MILESTONE_2030).isoformat(),
        )
    except Exception as exc:  # defensive: never kill a batch on one weird cert
        return CertRecord(sha256="", subject_cn=None, parse_error=repr(exc))
