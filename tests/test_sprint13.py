"""Sprint 13: cryptography at rest, to the extent it is observable.

The pipeline previously said it did not see at-rest cryptography, which was
true of the code and misleading about the problem. At rest is four layers and
only two are post-quantum problems: bulk AES is out of scope entirely, the
asymmetric wrapping layer is the exposure, signing keys run on a different
clock, and application-layer cryptography is invisible.

Three properties are pinned here.

1. **Tri-state, again.** An unrecognised key family resolves to `None` and is
   reported as unknown, never as safe. This is the F1 failure mode from sprint
   6 arriving on a third input path, and the one this project cannot afford to
   repeat, because the output is a number somebody budgets against.
2. **Two clocks stay apart.** Wrapping keys carry harvest-now-decrypt-later
   exposure; signing keys carry forgery-after-Q-day exposure on a longer and
   differently regulated horizon. They are counted separately, because a
   combined figure means nothing for either.
3. **Counts only.** Key identifiers, vault names and key ring paths are read
   for grouping and never written.
"""
from __future__ import annotations

import datetime as dt
import json

import pytest

from ananke.collectors.disclosure import assert_no_host_identifiers
from ananke.collectors.keys import classify, purpose, run, summarise
from ananke.collectors.sources import SectorLabelError


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("family", ["RSA", "rsa-hsm", "EC", "ECDSA", "DSA", "DH"])
def test_asymmetric_families_are_vulnerable(family):
    assert classify(family) is True


@pytest.mark.parametrize("family", ["ML-DSA", "kyber", "SLH-DSA", "xmss"])
def test_post_quantum_families_are_not(family):
    assert classify(family) is False


@pytest.mark.parametrize("family", ["AES", "oct", "oct-HSM", "hmac"])
def test_symmetric_is_counted_but_not_vulnerable(family):
    """AES-256 retains 128 bits against Grover. Counting it lets the report say
    "this part is fine" rather than leaving a client to assume the worst."""
    assert classify(family) is False


@pytest.mark.parametrize("family", ["SOMETHING-NEW", "", None, "unspecified"])
def test_an_unrecognised_family_is_unknown_not_safe(family):
    """F1 on a third input path. Reporting an unknown algorithm as safe is
    silent metric inflation and is treated as a security defect."""
    assert classify(family) is None


def test_unknown_families_are_reported_not_dropped():
    result = summarise([{"kty": "SOMETHING-NEW"}], "logistics")
    assert result["counts"]["quantum_vulnerable_unknown"] == 1
    assert "something-new" in result["key_families"]


# --------------------------------------------------------------------------- #
# two clocks
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ops,expected", [
    (["wrapKey", "unwrapKey"], "wrap"),
    (["sign", "verify"], "sign"),
    (["sign", "wrapKey"], "both"),
    (["encrypt", "decrypt"], "wrap"),
    ([], "unknown"),
    (None, "unknown"),
])
def test_purpose_separates_the_two_clocks(ops, expected):
    assert purpose(ops) == expected


def test_vulnerable_keys_are_split_by_purpose():
    """A wrapping key carries HNDL exposure; a signing key carries
    forgery-after-Q-day exposure on a different horizon. A combined count means
    nothing for either."""
    records = [
        {"kty": "RSA", "key_ops": ["wrapKey"]},
        {"kty": "RSA", "key_ops": ["sign"]},
        {"kty": "EC", "key_ops": ["sign"]},
    ]
    counts = summarise(records, "logistics")["counts"]
    assert counts["vulnerable_purpose_wrap"] == 1
    assert counts["vulnerable_purpose_sign"] == 2


# --------------------------------------------------------------------------- #
# the rotation finding
# --------------------------------------------------------------------------- #
def test_a_key_with_no_expiry_is_counted_as_the_agility_finding():
    """The strongest available at-rest finding needs no new observation: a key
    nobody planned to rotate is a key nobody planned to migrate."""
    counts = summarise([{"kty": "RSA"}, {"kty": "RSA", "expires": None}],
                       "logistics")["counts"]
    assert counts["no_expiry_set"] == 2
    assert "outlives_milestone" not in counts


def test_expiry_is_measured_against_the_configured_milestone():
    records = [{"kty": "RSA", "expires": "2032-01-01T00:00:00+00:00"}]
    strict = summarise(records, "logistics", milestone=dt.date(2030, 12, 31))
    loose = summarise(records, "logistics", milestone=dt.date(2033, 12, 31))
    assert strict["counts"]["outlives_milestone"] == 1
    assert loose["counts"]["expires_before_milestone"] == 1


def test_epoch_and_iso_expiry_are_both_understood():
    epoch = summarise([{"kty": "RSA", "exp": 1900000000}], "logistics")["counts"]
    assert "no_expiry_set" not in epoch


def test_rotation_policy_absence_is_distinguished_from_unknown():
    """A vault that reports no policy field at all is not the same as one that
    reports the policy as empty."""
    counts = summarise([
        {"kty": "RSA", "rotation_policy": {"expiryTime": "P2Y"}},
        {"kty": "RSA", "rotation_policy": None},
        {"kty": "RSA"},
    ], "logistics")["counts"]
    assert counts["rotation_policy_present"] == 1
    assert counts["rotation_policy_absent"] == 1
    assert counts["rotation_policy_unknown"] == 1


def test_hsm_backed_is_detected_from_the_family_suffix():
    counts = summarise([{"kty": "RSA-HSM"}, {"kty": "RSA", "hsm": True}],
                       "logistics")["counts"]
    assert counts["hsm_backed"] == 2


# --------------------------------------------------------------------------- #
# counts only, and the sector gate
# --------------------------------------------------------------------------- #
def test_no_identifier_reaches_the_written_output(tmp_path):
    export = tmp_path / "kms.json"
    export.write_text(json.dumps([
        {"kty": "RSA", "keySize": 2048, "key_ops": ["wrapKey"],
         "id": "https://prod-vault.vault.azure.net/keys/payments-kek/abc123",
         "vaultName": "prod-vault"},
    ]), encoding="utf-8")
    out = tmp_path / "key_inventory.json"
    payload = run(export, "logistics", out)

    blob = out.read_text(encoding="utf-8")
    for identifier in ("prod-vault", "payments-kek", "abc123", "vault.azure.net"):
        assert identifier not in blob
    assert_no_host_identifiers(payload)
    assert payload["disclosure_policy"]["granularity"] == "counts"


def test_export_shapes_are_tolerated(tmp_path):
    """ARG returns {"data": [...]}, aws returns {"Keys": [...]}, a hand-made
    export is often a bare list."""
    for body in ('[{"kty":"RSA"}]', '{"data":[{"kty":"RSA"}]}',
                 '{"Keys":[{"kty":"RSA"}]}'):
        export = tmp_path / "e.json"
        export.write_text(body, encoding="utf-8")
        payload = run(export, "logistics", tmp_path / "o.json")
        assert next(iter(payload["sectors"].values()))["keys_observed"] == 1


def test_a_hostile_sector_label_is_refused(tmp_path):
    export = tmp_path / "e.json"
    export.write_text('[{"kty":"RSA"}]', encoding="utf-8")
    with pytest.raises(SectorLabelError):
        run(export, "acme-bank.pl production", tmp_path / "o.json")


def test_the_symmetric_exclusion_is_stated_in_the_payload(tmp_path):
    """A client reading counts must be told why AES is present and excluded
    from migration scope, rather than left to infer it."""
    export = tmp_path / "e.json"
    export.write_text('[{"kty":"AES"}]', encoding="utf-8")
    payload = run(export, "logistics", tmp_path / "o.json")
    assert "Grover" in payload["scope_note"]
    assert payload["provenance"] == "reported"
