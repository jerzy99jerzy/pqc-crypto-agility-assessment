# Security policy

Project codename: ANANKE. Repository: `pqc-crypto-agility-assessment`.

## Why this file exists

This project makes two promises that are enforced in code rather than prose:
that no packet is sent to a third party's infrastructure, and that no host
identifier reaches committed output. Both are enforced by
`ananke/collectors/disclosure.py`, and three defects have been found in that
module across three sprints, each recorded in `docs/METHODOLOGY.md`. The fourth
will be found by somebody who is not the author, and that person needs a place
to send it.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(**Security** -> **Report a vulnerability**), which keeps the report out of
public issues until a fix exists. If that is unavailable to you, open an issue
containing only the words "security report" and a way to reach you privately,
with no technical detail.

Expect an acknowledgement within seven days. There is no bounty; this is a
single-maintainer project.

## What counts as a vulnerability here

The interesting attack surface is not remote code execution. It is the two
promises above, and anything that makes the measurement lie.

**In scope, high severity**

- Any input that causes a host identifier to survive into
  `data/aggregates/` or into `docs/report.md`. Certificate subjects, SANs,
  filenames, error strings and log lines all reach output paths.
- Any way to make the pipeline contact a third-party host. Modality A sends
  packets to `crt.sh` only; the active probe is restricted to hosts declared
  `self` or `reference` in the allowlist.
- Any way to make a sector bucket below the minimum size be emitted while the
  estate is not first party.
- Silent metric distortion: an unrecognised algorithm resolving to `False`
  rather than `None` inflates reported PQC adoption without any error. This has
  happened once (sprint 6) and is treated as a security defect, not a bug,
  because the product is the number.

**In scope, ordinary severity**

- Crashes or unbounded resource use from malformed certificates. Everything
  reaching `parse_certificate` is untrusted: CT is a public log anyone can
  write to, and since v0.9.0 the offline source parses files supplied by a
  third party.
- Path traversal or overwrite through `--pem-dir`, `--targets`, or an inventory
  export.
- Anything that causes the run journal or raw store to be written outside
  `data/`.

**Out of scope**

- Findings that require an attacker to already control the machine running the
  tool.
- The absence of authentication. There is none by design; this is a local CLI.
- Rate-limit avoidance against `crt.sh`. The limiter exists to be a good
  citizen, not to be a control.
- Detection-rule false positives or negatives. Those are correctness issues;
  open a normal issue.

## Handling of data

The raw store under `data/raw/` holds host-level records including certificate
subjects, and is git-ignored. Only sector-level aggregates are committed. If
you are reporting a defect, do not attach raw store contents, real client
inventories, or certificates from an estate you do not own. A synthetic
reproduction is always preferred; `tests/` shows how to generate one.

## Supported versions

The latest tagged release only. This is a single-maintainer project and there
is no backport branch.
