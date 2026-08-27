# Arenyxa v7.8 Architecture Consolidation

Arenyxa v7.8 is an architecture-consolidation release. The goal is to preserve the hardened network/security feature set while reducing the cost of installing, testing, tracing, and changing the runtime.

## 1. Runtime capability layers

The package no longer treats the desktop, browser automation, external packet dissection, distributed database, or telemetry stacks as one mandatory installation unit.

| Layer | Install surface | Runtime ownership |
|---|---|---|
| Core | base package | models, security, HTTPX transport, local state/control-plane primitives |
| Desktop | `.[desktop]` | PySide6 shell and XLSX-oriented desktop workflows |
| Analysis | `.[analysis]` | lxml/cssselect/DNS analysis helpers |
| Browser | `.[browser]` | Playwright/Chromium automation |
| Capture | `.[capture]` + optional OS tools | process attribution, HPACK, tshark/dumpcap integration |
| Server | `.[server]` | FastAPI/Uvicorn headless API |
| Database | `.[database]` | SQLAlchemy/PostgreSQL/MySQL distributed storage |
| Telemetry | `.[telemetry]` | OpenTelemetry exporters |
| Full | `.[full]` | production integration bundle |

A missing optional capability must degrade that feature, not make the entire application unimportable.

## 2. Request execution model

Modern Desktop/Server bootstraps use `AsyncRunOrchestrator`. The public run lifecycle remains synchronous/Future based so the Qt shell, persistent state machine, and existing extension points do not require a flag-day rewrite. Inside each run, network I/O is multiplexed by asyncio and HTTPX AsyncClient.

```text
Qt / CLI / Server
       |
       v
RunOrchestrator lifecycle boundary
       |
       +---- legacy/fallback ----> bounded request ThreadPoolExecutor
       |
       +---- modern v7.8 -------> AsyncRunOrchestrator
                                      |
                                      v
                                asyncio scheduler
                                  /    |    \
                                 /     |     \
                          global gate host gate adaptive rate
                                 \     |     /
                                  \    |    /
                                AsyncHttpFetcher
                                      |
                              pooled HTTPX sockets
                                      |
                            Parser -> Extractor -> Result
                                      |
                               batched persistence
```

The small outer run pool remains an isolation boundary for synchronous storage and UI-facing Future semantics. It is not the high-I/O request data plane.

## 3. Connection lifecycle

Both synchronous HTTPX fallback and async HTTPX paths reuse bounded connection pools. TCP/TLS sessions are no longer constructed and torn down for every ordinary request. Pools are closed by the owning orchestrator at deterministic shutdown boundaries.

## 4. Orchestrator decomposition

`application/runner.py` owns public lifecycle/admission/control APIs only. Request scheduling, host fairness, batching, request processing, and terminal execution transitions live in `application/run_execution.py`. The async data plane is isolated in `application/async_runner.py`.

The same ceiling is applied outside the runner: distributed health/readiness projection is isolated in `enterprise/distributed_health.py`, and external packet-row normalization is isolated in `infrastructure/capture/packet_row_projection.py`. Modern Python modules are held below the 1,000-line architecture gate so new capability growth must prefer composition over further monolithic accumulation.

Change rule: lifecycle/control-plane changes should not be mixed with transport/data-plane changes in one patch unless a contract test demonstrates the cross-boundary requirement.

## 5. State and data-flow trace

A normal run follows this trace:

1. `submit()` validates the immutable task snapshot and resource/enterprise policy.
2. A `Run` is durably created before execution is admitted.
3. The run worker enters `_execute`; modern runtime bridges to `_execute_async`.
4. Global request capacity, per-host capacity, and adaptive-rate reservation are acquired before network side effects.
5. DLP and network-governance checks run before DNS/socket activity.
6. HTTP responses are bounded by declared and observed byte limits.
7. Parser/extractor produces `ResultRecord`; retries/errors become explicit `_RequestOutcome` values.
8. Results are written in bounded batches; progress is periodically persisted.
9. Cancellation drains/cancels in-flight work and releases request/host leases exactly once.
10. A terminal `RunStatus` and finish timestamp are persisted even if final persistence itself fails.

This sequence is the primary debugging map for task execution. Correlation should start from `run.id`, then `request_index`, then destination host.

## 6. Legacy Windows boundary

Windows 7 remains a frozen Legacy Enterprise compatibility lane under `legacy/win7`. It does not define the modern Python/Qt feature ceiling. New v7.8 async execution, modern browser capabilities, and modern UI behavior are not required to be backported. Legacy validation is a separately invokable release dimension rather than a reason to put Python 3.8 constraints into modern modules.

## 7. Traffic automation reliability

Traffic automation rules now have deterministic priority, optional stop-processing semantics, arbitrary bounded top-level field patterns, cooldown and executions-per-minute guards, explicit failure policy, dry-run preview, update/enable controls, and execution statistics. These controls are intended to make rule behavior explainable and resistant to accidental event storms.

## 8. CI policy

Pull-request CI should prove core, architecture, static analysis, and desktop contracts without provisioning every enterprise capability. Heavy PostgreSQL, TShark, Playwright/Chromium, and full integration validation belongs in the capability-integration/release lane. This keeps contributor feedback fast while preserving release-grade gates.
