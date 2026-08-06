# Field run

Protocol for running the passive pipeline against a real target set, and the
record of what happened when it was run.

A run against public infrastructure behaves differently from a run against
`pqc-fixture`. Fixtures are complete, fast and well-formed by construction.
Certificate Transparency is none of those. This document exists so that the
difference is written down at the time rather than reconstructed later from
memory, and so that the next run does not rediscover the same failures.

---

## 1. Decisions to freeze before collection

Each of these is expensive to change afterwards, because changing it invalidates
the store and forces a repeat of the pull.

**Retention scope.** `CrtShClient.search` passes `exclude=expired` by default
and `--leaves` defaults to 2, so a store holds at most the two most recently
logged unexpired certificates per host. That is the correct scope for measuring
current posture. It is the wrong scope for anything that reads issuance history,
including the cadence proposal in `ROTATION-CADENCE.md`. A run intended to feed
both must widen `--leaves` and stop excluding expired entries, and must say so
here before it starts.

**Suppression threshold.** `pqc-select --min-bucket` and `pqc-collect
--min-bucket` are separate arguments with the same default. Nothing reconciles
them. A selection run at 5 followed by an aggregation run at 1 produces a
manifest and an aggregate that disagree about the disclosure policy, and the
report prints both without comment. Fix the invocation, or record the divergence
deliberately.

**Modality.** One store holds one modality. `MixedModalityError` enforces this,
but the cheaper control is not to point a first-party collection at a store that
already holds public CT records.

## 2. Command sequence

Under `tee`, always. A run whose failures were not captured cannot be described
later, which is the single most avoidable loss in this whole exercise.

```
export RUN_ID="$(date +%Y%m%d-%H%M)"
mkdir -p runs/"$RUN_ID"
pqc-select --ranking <ranking.csv> --suffix .pl --top <N> 2>&1 | tee runs/"$RUN_ID"/select.log
pqc-collect --targets config/targets.yaml -v 2>&1 | tee runs/"$RUN_ID"/collect.log
pqc-collect --aggregate-only 2>&1 | tee runs/"$RUN_ID"/aggregate.log
pqc-report --format md --out docs/report.md
```

`runs/` holds host names and stays out of version control.

## 3. Run record: 2026-08-06

Selection 01:35Z, aggregation 01:51Z. Ranking `top-1m.csv`, SHA-256 recorded in
the manifest, filters `.pl` and rank ≤ 138507, 1000 rows in scope after filters.

**Selection outcome.** 139 domains classified into nine sectors: government 47,
education 29, media 26, retail 12, telecom 9, finance 8, energy 5, healthcare 2,
legal 1. 861 rows unclassified. Healthcare and legal fell below the selection
threshold and were marked for downstream suppression.

**Collection outcome, partial.** The aggregate covers education only: 12 hosts
observed, 3 with a parsed certificate. Eight selected sectors produced no
records. The operator attributes this to errors returned by crt.sh during the
run.

**Failure modes: not captured.** The run was not put under `tee` and no journal
excerpt was preserved, so the errors are known to have happened and are not
known to have been rate limiting, query timeouts, 5xx responses, or a mixture.
This is recorded as a gap rather than guessed at. It is also the reason section
2 makes `tee` mandatory rather than advisory.

**Nine of twelve education hosts produced no certificate.** Ambiguous between an
incomplete collection and genuine CT silence for those names. The aggregate
reports `hosts_observed` and `hosts_with_certificate` separately, so the
ambiguity is visible, but nothing currently distinguishes the two causes. Worth
separating, because "no certificate in CT" is itself a finding and "we did not
finish asking" is not.

**Classification collisions on a real list.** Four domains matched rules from
more than one sector, resolved by config order, first match wins:
`energy.contains:oze | media.contains:radio`,
`finance.contains:fundusz | government.suffix:.gov.pl`,
`government.contains:samorzad | media.contains:portal`,
`government.suffix:.gov.pl | media.contains:portal`. Each is one domain. On a
sector the size of finance at 8, one domain is 12.5% of the denominator, so rule
order in `config/classification.yaml` is a free parameter that moves published
numbers. There is no sensitivity analysis for it. The collisions being counted
rather than resolved silently is what makes this visible at all.

**Suppression threshold disagreement.** The manifest records `min_bucket_size: 5`
and the aggregate records 1. Education at 12 hosts clears either, and nothing was
actually suppressed, so no disclosure occurred. The defect is that the two could
disagree without anything noticing.

**Disclosure guard.** No `DisclosureViolation` raised. `lint-disclosure` reports
0 violations across committed artefacts including the regenerated report.

**What the fixtures did not predict.** Fixture estates are fully populated, so
the host-without-certificate case, the partial-collection case and the
cross-invocation threshold divergence had no fixture analogue. All three
appeared on first contact with real data.

## 4. Open items this run produced

- Reconcile `min_bucket` across selection and aggregation, with a check that
  fails when they disagree.
- Distinguish "no certificate observed" from "host not collected".
- Sensitivity analysis for rule order in `config/classification.yaml`.
- Complete the collection across the remaining eight sectors, under `tee`.
- Characterise crt.sh failure modes from a captured log rather than from
  recollection.
