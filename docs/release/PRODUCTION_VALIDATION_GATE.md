# Arenyxa Production Validation Gate

Arenyxa separates **local crash/recovery correctness** from **real multi-node production evidence**. A one-host simulation is never promoted to production proof.

## Local destructive-failure gate

Run from a source checkout:

```powershell
$env:PYTHONPATH = "$PWD\src"
python scripts\production_validation.py --soak-jobs 256 --output production-validation-report.json
```

The local suite uses temporary data and the real `DurableDistributedQueue`. It covers hard process termination, non-idempotent side-effect fencing, terminal-response replay, concurrent lease exclusivity, checkpoint restart durability, impossible-future lease corruption, bounded multi-Worker soak, and concurrent batch-lease soak.

A local pass proves one-host crash/restart semantics only. It does **not** claim that a real network partition or independent-machine failure occurred.

## Real multi-node chaos gate

Production certification requires at least three **distinct SSH targets**: one Enterprise Server and two Workers. The deployment must use PostgreSQL distributed storage, TLS 1.3 minimum, and Enterprise protocol v2 or newer.

The chaos plan must execute all eight scenarios:

- `server_process_crash`
- `worker_process_crash`
- `network_partition`
- `duplicate_delivery`
- `delayed_delivery`
- `disk_pressure`
- `clock_discontinuity`
- `tls_identity_rotation`

Every scenario must be followed by post-cleanup verification probes covering one Server and two Workers. A scenario is not considered passed merely because its fault-injection command exited with status 0.

Each verification probe must emit one JSON object like this:

```json
{
  "host_id": "worker-01",
  "role": "worker",
  "healthy": true,
  "storage_backend": "postgresql",
  "tls_minimum": "TLSv1.3",
  "protocol_version": 2,
  "state_invariants": {
    "inconsistent_lease_rows": 0,
    "unreceipted_completed_jobs": 0,
    "implausible_future_leases": 0
  },
  "duplicate_terminal_receipts": 0,
  "uncaught_errors": 0
}
```

The runner stores SHA-256 target identities instead of raw SSH targets, records operation/output digests, verifies the node identity returned by every probe, and hashes the complete operation + verification record for each scenario.

Run the disruptive campaign only on operator-owned systems:

```powershell
$env:PYTHONPATH = "$PWD\src"
python scripts\multinode_chaos.py `
  --plan .\multinode-plan.json `
  --output .\multinode-chaos-evidence.json `
  --allow-disruptive-production-chaos
```

## 24-hour multi-node soak gate

The same plan must define `soak_probes` covering one Server and two Workers. Run:

```powershell
python scripts\multinode_soak.py `
  --plan .\multinode-plan.json `
  --chaos-evidence .\multinode-chaos-evidence.json `
  --duration-hours 24 `
  --sample-interval-seconds 60 `
  --output .\multinode-production-evidence.json
```

The production validator requires:

- at least 24 wall-clock hours;
- at least 96 recorded probe samples;
- one Server + two Workers represented in the soak;
- zero probe failures;
- zero uncaught errors;
- zero state-invariant violations;
- zero duplicate terminal receipts.

## Final evidence validation

The evidence schema is `arenyxa.production-multinode-evidence/v2`. The validator rejects self-asserted `"passed"` strings, missing node verification, aliased target identities, weak TLS, SQLite multi-host storage, scenario digest mismatches, short/incomplete soak runs, and any consistency failure.

```powershell
python scripts\production_validation.py `
  --multi-node-evidence .\multinode-production-evidence.json `
  --output .\production-validation-report.json
```

`production_ready=true` appears only when the local gate passes and the strict multi-node evidence is valid.
