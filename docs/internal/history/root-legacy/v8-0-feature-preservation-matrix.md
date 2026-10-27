# Arenyxa v8.0 — Feature Preservation Matrix

| Capability / contract | phase5 candidate baseline | phase6 candidate result | Phase 6 treatment |
|---|---|---|---|
| Desktop GUI / workbenches | Present | **Preserved** | Diagnostics/Performance consume shared survivability services |
| Developer CLI / terminal | Present | **Preserved + extended** | Adds `resilience` command group without removing existing groups |
| Application Control Plane | Present | **Preserved + extended** | Survivability/performance/drill methods added |
| Job System | Present | **Preserved** | Extended drills execute as persistent bounded jobs |
| Security Kernel / audit | Present | **Preserved** | New resources use existing capability checks; no bypass |
| Root Developer / Root Owner / TPM | Present | **Preserved** | No authority semantics relaxed |
| Zero Trust / DLP | Present | **Preserved** | No fail-open security change |
| Network Capture / Npcap / ETW paths | Present | **Preserved** | Existing queue/drop/backpressure semantics retained |
| Protocol Intelligence | Present | **Preserved** | Existing parser budgets and malformed-input isolation retained |
| Proxy Suite / MITM | Present | **Preserved** | Existing hot-path/history/replay/TLS contracts retained |
| Traffic Control Plane | Present | **Preserved** | No traffic-domain duplication |
| Enterprise identity/governance | Present | **Preserved** | No tenant/account/enrollment downgrade |
| Server / Worker / lease recovery | Present | **Preserved** | Worker-lease crash drill remains part of baseline campaign |
| SQLite local store | Present | **Preserved + hardened evidence** | New lock-contention drill proves bounded failure |
| PostgreSQL enterprise lane | Present | **Preserved** | No compatibility/API regression; real multi-host validation remains Phase 7/external |
| Recovery Center / runtime recovery | Present | **Preserved** | Exposed as survivability dependency; recovery audit retained |
| Safe Mode | Present | **Preserved + explicit state** | `safe_mode` is represented in survivability state/admission policy |
| Runtime supervisor | Present | **Preserved + extended** | Bounded incident listeners feed degradation state |
| Structured logging | Present | **Preserved + hardened** | stderr fallback on log sink failure |
| Diagnostics export | Present | **Preserved + extended** | Adds survivability/performance JSON evidence |
| Performance/resource governor | Present | **Preserved + extended** | Adds bounded p50/p95/p99 telemetry and explicit pressure state |
| Plugin manager/sandbox/signed trust | Present | **Preserved** | Failure isolation remains intact |
| Windows service/runtime control | Present | **Preserved** | Native Windows execution not falsely claimed on non-Windows host |
| Packaging / repair seed / source manifest | Present | **Preserved** | Version promoted to phase6 candidate; integrity artifacts regenerated |
| Windows 7 legacy lane | Present | **Preserved** | Release identity updated, feature freeze retained |

## No-regression statement

Phase 6 does not intentionally remove, downgrade, bypass, or replace any valid phase5 candidate capability. The only executable-file removal is the version-specific `verify_v80_phase5 candidate_release_identity.py`, replaced one-for-one by `verify_v80_phase6 candidate_release_identity.py`; this is a release-identity rename, not functional loss.

## Phase 6 preservation verification addendum

| Capability / contract | Phase 6 action | Status |
|---|---|---|
| Proxy durable history/archive | moved normal completion persistence behind bounded ordered writer; evidence-preserving fallback retained | PRESERVED + HARDENED |
| Proxy request hot path | removed normal synchronous dual persistence from completion path | HARDENED |
| Job System | existing persistence/cancel/timeout/progress retained; survivability workload admission added | PRESERVED + HARDENED |
| Recovery / Safe Mode | retained and integrated with explicit survivability diagnostics | PRESERVED + HARDENED |
| Resource Governor | retained; pressure state now drives bounded admission/cache/history actions | PRESERVED + HARDENED |
| Crawler | behavior retained; robots cache made bounded/LRU and pressure-trimmable | PRESERVED + HARDENED |
| Security / Audit / Root / TPM / Zero Trust | no bypass introduced; diagnostic degradation does not grant authority | PRESERVED |
| Enterprise / Server / Worker | Phase 4-5 control paths retained; Phase 6 failure/recovery semantics layered on top | PRESERVED |
| GUI / CLI | shared control-plane resilience/performance surfaces retained; no QWidget-only business logic added | PRESERVED + HARDENED |
| Packaging / compatibility identity | phase6 candidate product identity promoted; runtime/plugin compatibility remains `6.8.0` | PRESERVED |
