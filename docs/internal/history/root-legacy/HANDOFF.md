# HANDOFF.md — next Bot only

## Current State

- Product version label in installer/spec: Arenyxa 8.2.0
- Baseline of **this package**: cleaned extract of `Arenyxa_v8.1.1_CLEAN_SOURCE.txt` **plus** Phase 6.1 follow-up edits listed below
- Original workspace dump tree `artifacts/arenyxa_src` (if you see it): **do not touch**. It still has `====` dump trailers. Pytest cannot parse that tree’s `tests/conftest.py`.
- No `.git` in this snapshot
- Host that last ran tests: Linux, 2 vCPU, ~2 GiB RAM, no PostgreSQL, no Windows VM

## What Was Changed (Phase 6.1 only)

| File | Why |
|------|-----|
| `src/arenyxa/security/models.py` | DS-002: missing identity no longer `KeyError` |
| `legacy/win7/src/arenyxa/security/models.py` | same contract on legacy tree |
| `src/arenyxa/enterprise/job_lifecycle.py` | **new** Design A wrapper |
| `tests/test_bug_ds002_identity_missing.py` | **new** regression |
| `tests/test_job_lifecycle_ownership.py` | **new** fake-queue ownership unit tests |
| `tests/test_workflow_dataset_v65.py` | strip dump BINARY inventory so file parses |
| `tests/test_phase4_security_foundation.py` | assertion widened to also accept `KEY_PROTECTION_UNAVAILABLE` on non-Windows |

`DurableDistributedQueue.lease_next` / `start_job` / `complete` / `fail` **signatures were not changed**.

## What Was Verified

UNIT / REGRESSION on this tree (command in `evidence/TEST_RESULTS.txt`):

- `test_bug_ds002_identity_missing.py` — PASS
- `test_job_lifecycle_ownership.py` — PASS (mocked queue, **not** PostgreSQL)
- `test_proxy_persistence_lifecycle.py` — PASS (DS-001 unit)
- `test_workflow_dataset_v65.py` — PASS after extract repair
- `test_data_lineage_v64.py` — PASS (DS-006 slice)
- `test_phase4_security_foundation.py` — PASS **after** the assertion widening

Recorded aggregate: **30 passed** for that exact pytest invocation.

## What Was Not Verified

INTEGRATION NOT RUN — real PostgreSQL DurableDistributedQueue + JobLifecycle
CONCURRENCY NOT RUN — 8/32/64/128 workers
PRODUCTION GATE NOT RUN — `scripts/postgresql_64_worker_128_concurrency_gate.py`
WINDOWS NOT RUN — no VM, no EXE, no installer
FULL SUITE NOT RUN — 178 test modules exist; only the list above was executed
DS-003 / DS-005 / DS-007 — no dedicated passing proof this phase
Navigation product contract — draft only, no UI run

## Known Risks

1. `JobLifecycle.acquire_job` calls `lease_next` then `start_job`. If `start_job` raises, the job can remain **leased** with no handle returned. Wrapper does not `fail()` on that path.
2. Ownership tests use `_FakeQueue`. They cannot prove pool occupancy, SKIP LOCKED, fencing, or checkout/checkin.
3. `ClaimedJob` stores a live `payload` mapping from the lease object; callers can mutate payload contents if the mapping is not copied.
4. `revoke_device` still uses `self._devices[id]` → **KeyError** on missing device (same class of bug as DS-002, not fixed).
5. Phase 6.1 changed a security unit assertion (`NOT_CONFIGURED` → also `UNAVAILABLE`). That is a **test-contract change**, not a TPM production fix.
6. 2 vCPU numbers from earlier phases are not SLAs.

## Known Bugs / statuses

| ID | Status in this package |
|----|------------------------|
| BUG-DS-001 enqueue/close race | UNIT PASS on lifecycle tests. Not concurrency-certified. |
| BUG-DS-002 identity KeyError | Code + unit regression PASS on modern and legacy copies of the two methods. Device `revoke_device` still KeyError. |
| BUG-DS-003 workflow token leak | NOT VERIFIED |
| BUG-DS-004 quoted `\|` | NOT VERIFIED as a named case (v80 suite was run in 6.1 continuation, not re-stated as full proof here) |
| BUG-DS-005 proxy stop/intercept | NOT VERIFIED |
| BUG-DS-006 lineage | UNIT PASS `test_data_lineage_v64.py` only |
| BUG-DS-007 auth rollback/audit | NOT VERIFIED |
| BUG-WIN-0001 sidebar vs registry | DRAFT contract only |

## Design Decisions

- Design A is a **candidate wrapper**. Queue remains the source of truth for SQL, fencing (`lease_token` SHA256), pool checkout, recover.
- Do not promote `JobExecutionSession` pin (Phase 4/5 experimental) into production.
- Do not hold a DB connection across application work.
- Sidebar cap of 8 is encoded in `NavigationPolicyEngine`; do not assume Registry == sidebar.

## Forbidden Assumptions

- “30 passed” ≠ Phase 6 official PASS
- Design A ≠ production-certified ownership
- Clean zip ≠ git history or signed release
- Linux unit tests ≠ Windows packaged behavior
- Widened TPM test ≠ Windows TPM verified

## Next Recommended Step

When the human opens the next phase (not before):

1. Independent takeover: re-read `job_lifecycle.py` and `SecurityState` against this file; re-run the same pytest command.
2. Add a real-PG test for `JobLifecycle` that measures occupancy during `sleep()` after `acquire_job`, **or** explicitly keep Design A experimental.
3. Decide product contract for sidebar before editing `NavigationPolicyEngine`.
4. Do not merge into `artifacts/arenyxa_src`.
