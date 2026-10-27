# Arenyxa Distributed State Consistency Hardening

Status: v7.0 hardened development baseline (2026-08-17)

## Purpose

The distributed queue must prefer a deterministic, reviewable state over automatic availability when ownership or side-effect facts are ambiguous. SQLite transactions protect normal writes; the rules below protect cross-process, cross-machine, restart, and transport-loss boundaries.

## Terminal completion receipt

A completed job persists a receipt bound to:

- Worker ID;
- SHA-256 of the lease token (the raw lease token is never persisted);
- canonical result SHA-256;
- terminal timestamp.

An exact duplicate completion is accepted. This covers the case where the Server committed the completion but the response was lost. A different Worker, lease token, or result is rejected with `DISTRIBUTED_TERMINAL_CONFLICT`. A duplicate receipt must not create another state-transition journal entry or decrement Worker lease accounting twice.

## Durable transition journal

`distributed_job_events` records bounded state evidence for each Job. The current limit is 128 recent events per Job. It is intentionally not an unlimited event stream.

Important transitions include:

- enqueued;
- leased;
- started;
- non-idempotent side-effect fence;
- completion;
- execution failure/requeue;
- lease expiry recovery;
- Worker revoke recovery;
- startup lease reconciliation;
- explicit operator retry from `review_required`.

The journal stores no lease token, bearer token, Vault secret, private key, or task payload.

## Startup reconciliation

On queue open, Arenyxa recalculates derivable Worker `active_leases` counters from authoritative Job rows. Impossible lease ownership is recovered before normal operation, including:

- leased/running Job without Worker ID;
- missing lease-token digest;
- non-positive expiry;
- missing Worker record;
- revoked Worker owning a lease;
- an expiry implausibly farther in the future than the protocol permits.

Expired persisted leases are also recovered during startup, rather than waiting for a later Worker poll.

### Recovery rule

If a non-idempotent Job has `side_effect_state=started`, loss of trustworthy lease ownership always becomes `review_required`. It is never automatically replayed.

Otherwise, an idempotent/retry-safe Job is requeued only while its attempt budget remains. Exhausted work becomes `failed`.

## Worker completion retry

The network Worker may retry the exact completion request once after a transient transport failure. This is safe only because the Server terminal receipt makes the request idempotent. TLS/identity/trust failures are never treated as transient availability failures.

Checkpoint writes are not automatically replayed as terminal requests; their sequence semantics remain authoritative on the Server.

## Health invariants

Distributed health reports include:

- last startup reconciliation counts;
- inconsistent lease-row count;
- completed Jobs missing a modern terminal receipt (useful for legacy/migration visibility);
- durable transition-journal event count.

These are operational diagnostics. A non-zero legacy receipt count does not permit mutation or downgrade of an already-completed Job.

## Non-negotiable invariants

1. A raw lease token is never persisted.
2. Completion can be acknowledged twice only when Worker + lease digest + canonical result hash all match.
3. Completion conflict never overwrites terminal state.
4. `review_required` cannot be automatically converted into runnable work; operator retry requires the existing governance/step-up path.
5. Non-idempotent started side effects are never automatically replayed after ambiguous ownership loss.
6. Derived Worker lease counters are not trusted over authoritative Job rows.
7. Startup recovery must not guess that an external side effect did or did not happen.
8. Transition evidence is bounded and must not contain secrets.

## Remaining native/failure-drill gates

Automated tests cannot replace real multi-machine validation. Release evidence still requires at least one Enterprise Server and two Workers on separate Windows hosts, including partition, process termination, reboot, delayed/duplicated delivery, TLS identity rotation, disk-full/storage interruption, and clock-adjustment drills.
