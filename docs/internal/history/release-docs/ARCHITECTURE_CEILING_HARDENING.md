# Arenyxa v7.0 Architecture Ceiling Hardening

This hardening pass targets six previously identified architecture ceilings without weakening the existing local-first runtime.

## 1. Distributed runtime storage

`DurableDistributedQueue` no longer owns SQLite connection/schema/dialect details. The new `enterprise.runtime_storage` boundary provides:

- `SQLiteDistributedRuntimeStorage` as the zero-administration local default.
- `PostgreSQLDistributedRuntimeStorage` for external multi-host Enterprise queue state.
- backend capability reporting so the runtime does not infer guarantees from a filename.
- PostgreSQL row-lock queue selection with `LIMIT 1 FOR UPDATE SKIP LOCKED`.
- serialized PostgreSQL schema initialization through an advisory transaction lock.
- a DSN-file launch path in `scripts/enterprise_server.py` so credentials need not be placed directly in process arguments.

This pass ports the **distributed queue/control-plane state**, not the entire historical `SQLiteStore` Dataset/application repository. A broader repository abstraction remains separate future work.

## 2. Qt compatibility lanes

The Modern lane remains active development. Legacy Enterprise is now explicitly feature-frozen and security/critical-maintenance only; new Modern features do not require feature parity. See `LEGACY_RUNTIME_MAINTENANCE_POLICY.md`.

## 3. Workflow large-data bounding

Dataset-to-Workflow checkpointing now flushes on three independent bounds:

- processed/output count,
- pending serialized output bytes,
- maximum checkpoint wall-clock interval.

A single output larger than the configured pending-byte ceiling fails explicitly. This reduces memory and recovery-latency risk but does not claim complete streaming fan-in/backpressure semantics for arbitrary DAGs.

## 4. Dynamic regex isolation

User-controlled regex extraction/replacement/validation is executed in a short-lived spawned process with a hard wall-clock deadline and bounded pattern/input/replacement sizes. A catastrophic backtracking regex can therefore be terminated by the parent process rather than occupying the main runtime indefinitely.

Internal constant regexes remain in-process.

## 5. HTTP transport

`HttpFetcher` now has a transport boundary:

- `httpx` is the Modern/default path when installed.
- `urllib` remains an explicit compatibility fallback.
- connect/read/write/pool timeouts are bounded separately in the HTTPX path.
- streamed response reads retain Arenyxa's response-size ceiling and cancellation checkpoints.

Synchronous socket cancellation is still bounded by transport timeouts; this pass does not claim that an arbitrary in-flight OS socket can always be interrupted instantaneously.

## 6. Plugin resource containment

Windows Job Object containment remains intact. POSIX plugin workers now apply kernel resource ceilings before loading plugin code (CPU, address space where available, file size, descriptors, core dumps) and Linux applies `PR_SET_NO_NEW_PRIVS` where available.

This is stronger resource containment, **not** a container/VM-grade security sandbox. Filesystem/network/process capability policy still depends on the existing audit-hook boundary.

## Validation boundary

The existing SQLite path and distributed semantics remain the compatibility baseline. PostgreSQL code is structurally tested in this source tree, but a real PostgreSQL service/driver was not present in the hardening environment, so live multi-Coordinator PostgreSQL validation remains required before declaring that backend production-proven.
