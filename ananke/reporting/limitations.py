"""What the assessment does not tell you, in the short form the reports print.

The long form is the README section "What this assessment will not tell you",
and `tests/lint_limitations.py` registers each of its bullets with probes. Until
0.15.2 the markdown and HTML renderers each carried a private copy of the list,
and both copies still opened with "Cryptography at rest." in 0.13.0, the
release that found that flat claim false, and in the seven tagged releases
after it. The README was corrected and checked; the report was neither.

Both renderers now print this tuple, and the lint fails when its keys and the
README registry disagree, so a limitation cannot change in one place only.

Each entry is (registry claim key, sentence printed in the report). Keys must
match `REGISTRY[*]["claim"]` in `tests/lint_limitations.py` exactly. Sentences
are plain text: the HTML renderer escapes them and does not interpret markup.
"""

from __future__ import annotations

LIMITATIONS: tuple[tuple[str, str], ...] = (
    (
        "Bulk data encryption is not in migration scope",
        "Bulk data encryption (volumes, databases, object stores under AES) is "
        "not in migration scope: AES-256 keeps 128 bits of strength against Grover.",
    ),
    (
        "The key-wrapping layer is the real at-rest exposure",
        "At rest, the exposure is the layer of RSA and EC keys that wrap data "
        "keys. It is counted from an operator-supplied key management export "
        "(pqc-keys), not from certificate data.",
    ),
    (
        "Signing keys run on a different clock",
        "Signing keys carry forgery risk on their own horizon, which the HNDL "
        "score does not measure.",
    ),
    (
        "Application-layer cryptography is not observable",
        "Application-layer cryptography, such as keys compiled into binaries or "
        "encryption written by hand in application code, is not observable.",
    ),
    (
        "does not see HSM internals beyond the attributes",
        "HSM internals beyond the attributes a key management API exposes, and "
        "keys held outside any managed service, are not observable.",
    ),
    (
        "does not see internal PKI, except indirectly",
        "Internal PKI is visible only indirectly, through endpoint certificate "
        "inventory in the detection layer.",
    ),
    (
        "does not see code, embedded libraries, or pinned certificates",
        "Code, embedded libraries and certificates pinned inside applications "
        "are not observable.",
    ),
    (
        "negotiated key exchange group of third-party services",
        "The key exchange group a third-party service negotiates is not "
        "observable from certificate data. It needs an active handshake, which "
        "is not performed against third-party estate.",
    ),
    (
        "A certificate that uses RSA says nothing",
        "A certificate that uses RSA says nothing about whether the same service "
        "already negotiates a hybrid group.",
    ),
)
