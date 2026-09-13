# ARENYXA v8.2 — Phase 7C Host / Instance Attribution

## Frozen purpose

Estimate between-host variance separately from fresh-PostgreSQL-instance-within-host variance under the unchanged production-equivalent workload. This campaign is diagnostic only and cannot itself authorize a production patch.

## Source identity

- Production base commit: `3726289355ebe2a253ae8da1b8b4645e01244830`
- Authoritative source ZIP SHA-256: `72360b9e1598fa1c2f3166f9637ab012342c404d6ff38d3269c5f659eb05be0f`
- Production source changes on this branch: **forbidden**

## Experimental units

- Primary unit: independent GitHub-hosted runner / host
- Hosts: 4
- Nested unit: fresh PostgreSQL 16.15 container/instance
- Instances per host: 3
- Retained first-use runs per instance: 1
- Natural-warm runs per instance: 60
- Total planned natural-warm runs: 720
- Total planned retained first-use runs: 12

## Frozen workload

64 workers, 128 concurrent tasks, 1024 jobs, 16 clients, PostgreSQL `max_connections=256`, `fsync=on`, `synchronous_commit=on`, existing queue/lease/fencing semantics, P99 release budget 500 ms, engineering target below 300 ms.

## Observer

Reuse only the Phase 8R run-boundary OS+PostgreSQL snapshot profile after per-host calibration. No timed hot-path SQL and no per-job observer query are added.

## Predeclared adjudication

The four host artifacts must all be retained. Runs or hosts cannot be removed after seeing latency. Correctness failure invalidates performance PASS for the affected instance but does not delete its raw evidence. Host-level causal promotion requires replication beyond one fast and one slow host; this campaign is designed to supply that missing hierarchy.
