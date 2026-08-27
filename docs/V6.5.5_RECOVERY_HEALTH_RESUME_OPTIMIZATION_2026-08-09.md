# Arenyxa V6.5.5 — Recovery, Health & Resume Optimization

## Scope

V6.5.5 turns the V6.5.4 runtime-recovery substrate into a user-visible, bounded control surface. The release focuses on recovery correctness, concurrency safety, health observability, and low-impact diagnostics rather than adding unrelated feature breadth.

## Recovery & Health Center

A new **Recovery & Health Center** is registered in the Advanced navigation group. It exposes read-only runtime health plus narrowly-scoped recovery actions:

- resumable and blocked Workflow executions;
- interrupted Dataset Revisions;
- Scheduler state including enabled/running/pending/overdue information;
- configured Distributed Workers without doing network I/O on ordinary refresh;
- an explicit concurrent Worker health probe;
- the bounded runtime recovery history produced by startup recovery;
- one-click Workflow resume when the durable checkpoint chain is valid.

The page uses single-row selection for recovery actions and does not expose the broad installation repair operation. `RuntimeRecoveryService.recover()` assumes persisted active records may belong to a previous process; invoking that operation indiscriminately while the current process is healthy could incorrectly classify live work as stale. Installation/file repair therefore remains in the dedicated Repair Center.

## Atomic Workflow Resume Claim

V6.5.4 could validate an interrupted execution and then begin resume, but two independent UI/API callers could theoretically pass the validation read before either changed the row state. V6.5.5 adds `SQLiteStore.claim_workflow_execution_for_resume()`.

The claim is a transaction-level compare-and-set operation:

1. Require execution state `interrupted` or `cancelled`.
2. Verify the output Revision exists and is not `ready`.
3. Update the execution to `running` only if its state still equals the observed state.
4. Reopen the output Revision to `building` in the same transaction.
5. Roll back the transaction if either side cannot be claimed safely.

Only the winner can write subsequent Workflow checkpoints. `checkpoint_workflow_execution()` now requires the execution to already be `running`, preventing an unclaimed interrupted execution from implicitly re-entering execution through a checkpoint write.

## Scheduler Snapshot Contract

`SchedulerService.snapshot()` copies a small public runtime view while holding the scheduler condition lock. The snapshot intentionally omits callback objects and exposes only:

- schedule ID;
- rule kind and timezone;
- enabled state;
- next-run timestamp;
- current running state;
- whether a callback Future is pending.

This prevents UI and diagnostic code from reaching into mutable private dictionaries while the scheduler thread is rescheduling jobs.

## Distributed Worker Health

`DistributedWorkerService.health_all()` probes enabled workers with a bounded thread pool. One offline worker no longer aborts the entire health scan or forces the dashboard to wait serially for every five-second timeout. Disabled workers are reported without network access. Remote failures are normalized into bounded diagnostic strings.

Ordinary Recovery Center refresh performs **no remote Worker network I/O**. Network probing is an explicit user action.

## Dataset Recovery Boundary

Interrupted Dataset Revisions are displayed, but V6.5.5 deliberately does not present an automatic `Resume Dataset Revision` action unless the original transformation/run semantics are durably sufficient to reproduce the write stream. Preserving a partial Revision does not imply that an arbitrary source operation is replay-safe. This avoids inventing identity fields, pagination state, or external side effects during recovery.

## Localization

The new Advanced navigation destination and Recovery Center shell are catalogued across all ten supported locales. Dynamic human-facing recovery status text is localized through the same stable literal catalog; technical IDs, URLs, timestamps, counters, exception types, and raw recovery history remain unchanged.

## Performance and stability posture

- local health refresh remains side-effect-free and does not perform network access;
- Worker probes are explicit and bounded;
- Scheduler state is copied under lock;
- Recovery history reads are capped at 2 MiB and the latest 50 structured entries;
- recovery table actions are single-selection;
- Workflow resume ownership is atomic at SQLite transaction level;
- completed Dataset Revisions remain immutable;
- no automatic recovery path deletes user records.

## Verification

V6.5.5 adds regression coverage for concurrent Resume claims, checkpoint ownership, Scheduler snapshots, partial Worker outages, Recovery Center navigation, selection contracts, and localization registration. Full suite results and release artifact verification are recorded during the final release build.
