# Arenyxa v8.0 Shared Platform Control Plane

This document is the implementation map for the v8.0 application-service boundary. It supplements the preserved v7.8 execution architecture; it does not replace or bypass any existing capture, replay, proxy, protocol, enterprise, storage, recovery, plug-in, or automation service.

## Entry surfaces and ownership

```text
Qt GUI terminal ---------+
CLI ---------------------+-- CommandRuntime --+
Server REST API ---------+                    |
Worker heartbeat -----------------------------+
                                                v
                                    PlatformControlPlane
                                      /       |       \
                              SecurityKernel  |    JobSystem
                              RBAC/Policy/Audit|  bounded/persistent
                                              |
                         +--------------------+--------------------+
                         |                    |                    |
                     Database          Diagnostics export   Existing services
                 integrity/jobs        redaction + hashes   runner/capture/
                                                          proxy/MITM/plugin/
                                                          enterprise/supervisor
```

`PlatformControlPlane` is the single application-service implementation for platform health, diagnostic exports, and job inspection/control. CLI and GUI terminal commands reach it through `CommandRuntime`; Server routes call the same service directly; Worker heartbeat projection reads the same health model. Business behavior is not copied into those adapters.

## Security boundary

Every platform operation has an explicit capability and resource:

| Operation | Capability | Resource pattern | Audit behavior |
|---|---|---|---|
| Health/readiness | `project.read` | `health:platform` | authorization decision plus caller correlation |
| Diagnostic export | `logs.read` | `diagnostics:export` | admission and terminal job decision |
| List/show/wait jobs | `logs.read` | `job:*` | policy-enforced read |
| Cancel job | `system.configure` | `job:<id>` | policy-enforced mutation plus terminal audit |

Desktop/CLI bootstrap creates a local control session with narrowly scoped policy rules. Server tokens are mapped to roles and server-owned sessions, then pass through the same `SecurityKernel`. Unauthenticated server access to platform endpoints is rejected. Diagnostic logs are bounded and redact bearer tokens, passwords, secrets, private keys, and common credential forms before being written.

## Job lifecycle and persistence

Long-running platform work is admitted by `JobSystem`, not executed on the Qt event thread or request adapter:

```text
authorize -> acquire bounded slot -> persist queued -> worker running
          -> progress/cancel/timeout checks -> terminal audit
          -> persist succeeded|failed|cancelled|timed_out -> release slot
```

The queue is bounded by worker and queue capacities. Overload returns `JOB_BACKPRESSURE`. Startup recovery converts orphaned `queued` or `running` rows to `interrupted`, so a process restart cannot leave fake-active work. Shutdown stops admission, requests cooperative cancellation, drains workers within its budget, and then closes dependent services.

## Storage contract

The existing SQLite migration path now creates `platform_jobs` and indexes for state/time lookup. Results and errors are JSON serialized with a one-MiB upper bound. State transitions use expected-state guards. Storage health performs `PRAGMA quick_check` and verifies the job schema rather than returning a constant status.

## Health and diagnostics contract

The health schema is `arenyxa.platform-health/v1`. A deep probe reports database integrity, audit-chain integrity, job admission/recovery state, process resources, and live state from existing runner, capture, proxy, MITM, plug-in, supervisor, and enterprise services. A missing optional service is reported as unavailable; it is not fabricated as healthy.

Diagnostic export runs as a persistent job and writes a ZIP atomically. The bundle contains a machine-readable manifest, health snapshot, redacted bounded log excerpts, and SHA-256 hashes. The ZIP is reopened and verified before the job reports success.

## Compatibility and extension rules

- Existing `/health` response compatibility is preserved while adding the v8 platform projection.
- Existing command groups and service implementations remain authoritative for their domains.
- New GUI, CLI, Server, or Worker platform features must enter through an application service and must not reproduce domain logic in the adapter.
- High-risk operations require a registered capability, an explicit resource, policy evaluation, and audit evidence.
- Work that can block must be submitted to `JobSystem` or an existing bounded background orchestrator.
- Optional integrations must report unavailability and retain deterministic shutdown behavior.
