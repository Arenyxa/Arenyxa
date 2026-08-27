# Enterprise Distributed Storage Capacity

Arenyxa supports two persistence envelopes for the Enterprise distributed runtime:

- **SQLite WAL** — durable, embedded, single-host storage with serialized writers.
- **PostgreSQL** — external concurrent-writer storage for sustained high concurrency and multi-host deployments.

## Capacity policy

SQLite durability settings are intentionally not weakened to chase synthetic throughput. Instead, Arenyxa publishes a runtime capacity assessment containing:

- registered Worker count;
- total configured Worker slots;
- active leases;
- recommended total Worker slots;
- high-concurrency cutover threshold;
- oversubscription ratio;
- severity (`healthy`, `warning`, `critical`);
- an explicit `postgresql_recommended` decision.

The current SQLite envelope is conservative:

- recommended total Worker slots: **8**;
- high-concurrency cutover: **16 total slots or 16 Workers**.

These values are operational guardrails, not claims about a universal benchmark maximum. Hardware, workload shape, storage media and checkpoint frequency all change the exact latency curve.

## Operational rule

When `capacity.postgresql_recommended=true`, migrate the Enterprise distributed runtime to PostgreSQL rather than changing SQLite `synchronous`, WAL durability, or integrity policy solely to reduce benchmark latency.

The Server `/enterprise/v1/ready` response remains ready when state integrity is valid, but reports `degraded=true` for a critical capacity assessment. This avoids turning a capacity warning into an artificial outage while still making the condition machine-readable.
