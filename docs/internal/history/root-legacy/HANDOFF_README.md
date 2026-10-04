# HANDOFF README

这是 Phase 6.1 Follow-up Handoff Package，不是最终生产认证包。

Do not treat this zip as production-certified Arenyxa v8.1.1.
Do not merge this tree into the original production extract without a new forensics + gate phase.

## First thing the next Bot must do

1. Read this file completely.
2. Read `HANDOFF.md`.
3. Read `IMPLEMENTATION.md`.
4. Read `PHASE_6_1_STATUS.md`.
5. Read `evidence/TEST_RESULTS.txt`.
6. Treat `src/` in **this zip** as the candidate follow-up baseline.
7. Treat `/artifacts/arenyxa_src` (if present in the originating workspace) as the **untouched polluted dump extract**. Do not edit it.
8. Do **not** start Phase 6.2 until the human explicitly asks.

## What this package is

A cleaned v8.1.1 source snapshot plus Phase 6.1 candidate changes:

- DS-002 KeyError → `ArenyxaError IDENTITY_INVALID`
- Design A wrapper `JobLifecycle` / `ClaimedJob`
- repaired `tests/test_workflow_dataset_v65.py` extract junk
- unit/regression tests that were actually executed on this tree

## What this package is not

- Not official PostgreSQL 64-worker / 128-concurrency gate PASS
- Not Windows VM / installer PASS
- Not production merge approval
- Not “Phase 6 all gates passed”
- Not a replacement of `lease_next` / `start_job` / `complete` as the only API
