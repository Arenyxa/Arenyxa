# Arenyxa V8.1

Release: **Arenyxa V8.1** (`8.1.0`). It preserves the v8.0 runtime, database, Security Kernel, Supervisor, Enterprise, Developer, Root, Server/Worker, Recovery, and existing feature surfaces while introducing a unified identity-driven Experience Context.

Arenyxa v8.1 is the stable source release of the Windows-first, Desktop-first, CLI-complete, Server-capable and Worker-capable Arenyxa network and security platform. It consolidates the Phase 1-7 platform upgrade while preserving the established Capture, Protocol Intelligence, Proxy/MITM, Security Kernel, TPM/Root, Zero Trust, Enterprise, Server/Worker, Recovery, Terminal, packaging and regression contracts.

The public runtime compatibility version remains `8.1`, the established plugin-facing package compatibility identity remains `8.1.0`, the PEP 440 distribution version is `8.1.0`, and Windows file metadata remains `8.1.0.0`. Plugin/runtime compatibility intentionally remains `6.8.0`; the V8.1 stable release preserves established plugin and distributed compatibility semantics. Windows 7 remains a feature-frozen legacy lane.

Final local engineering acceptance is evidence-driven. Native Windows/Npcap/ETW/WFP/DPAPI/TPM-CNG/SCM, live PostgreSQL multi-node and TShark differential certification remain environment-dependent and must be reported as `NOT EXECUTED` when those prerequisites are unavailable.

## Download, source, and official websites

- Download Arenyxa (latest formal release): [https://github.com/Arenyxa/Arenyxa/releases/latest](https://github.com/Arenyxa/Arenyxa/releases/latest)
- Source code and repository: [https://github.com/Arenyxa/Arenyxa](https://github.com/Arenyxa/Arenyxa)
- Flagship experience: [https://arenyxa.pages.dev/](https://arenyxa.pages.dev/)
- Official introduction: [https://arenyxa.github.io/](https://arenyxa.github.io/)

Release downloads contain the published installer assets. GitHub's automatically generated source archives are source code, not Windows installers.

## V8.0 platform hardening carried forward


- `SurvivabilityManager` provides explicit `normal`, `degraded`, `resource_pressure`, `read_only`, `recovering`, and `safe_mode` states instead of silent partial failure. Transitions are bounded, persisted for diagnostics, and expose an admission policy that keeps read/diagnostic/audit paths available while suppressing unsafe heavy work or noncritical writes.
- CPU, memory, disk, browser, and worker pressure are sampled through the existing `SystemResourceProbe` / `ResourceGovernor`; critical disk pressure enters read-only mode, CPU/memory pressure reduces adaptive ceilings, and recovery is gradual rather than an immediate concurrency spike.
- `PerformanceTelemetry` records bounded latency samples, counters, and gauges with p50/p95/p99 summaries. Metric names and samples are budgeted so telemetry cannot become an unbounded memory sink.
- Runtime-supervisor incidents can feed the survivability state machine. A detected component/event-loop stall remains isolated, keeps diagnostics available, and records the component and diagnostic path instead of collapsing the process-wide health view into an unexplained failure.
- The shared `PlatformControlPlane` exposes survivability and performance snapshots and runs the extended Phase 6 failure drills through the persistent Job System. Diagnostic ZIPs now include `survivability.json` and `performance-telemetry.json`.
- CLI parity is provided through `arenyxa resilience status`, `resilience refresh`, `resilience performance`, and `resilience drills`. GUI Diagnostics and Performance workbenches consume the same control-plane services rather than duplicating business logic.
- The original four periodic resilience drills are preserved for compatibility. Phase 6 adds an extended seven-drill campaign covering worker lease recovery, synthetic 50% network loss with bounded retries, delayed-disk checkpoint integrity, runtime recovery audit, SQLite lock backpressure, corrupt-settings fallback, and resource-pressure degradation/recovery.
- Existing bounded queues, async HTTP connection reuse, SQLite contention controls, PostgreSQL pooling, capture/drop accounting, proxy persistence hardening, parser budgets, Job System cancellation/timeout, Safe Mode, Recovery UI, and startup recovery remain preserved and are validated as regression dependencies of this phase.

### Phase 1-5 capabilities retained

- Modern Desktop and Headless Server task runs use `AsyncRunOrchestrator`; HTTPX transports reuse bounded TCP/TLS connection pools while the synchronous transport remains the explicit compatibility fallback.
- `PlatformControlPlane`, `TrafficControlPlane`, and `EnterpriseControlPlane` remain the shared application-service boundaries for GUI, CLI, Server, Worker, and automation surfaces.
- Network Capture, Protocol Intelligence, Proxy Suite, MITM, API Security Lab, Traffic Forensics, Enterprise identity/governance, Server/Worker lease execution, Windows runtime/service controls, signed plugin trust, Security Kernel, Audit, Job System, Storage, Recovery, and Diagnostics remain connected.
- Base installation stays modular; optional desktop, capture, browser, analysis, server, database, and telemetry extras remain available.

### Professional CLI examples

```powershell
arenyxa proxy status
arenyxa proxy history --page 1 --page-size 100
arenyxa proxy sessions
arenyxa proxy intercept enable --responses
arenyxa proxy intercept list
arenyxa proxy replay <flow-id> --confirm-side-effect
arenyxa tls status
arenyxa tls certificates
arenyxa api analyze --limit 10000
arenyxa analyze traffic --limit 10000
arenyxa enterprise status
arenyxa recovery check
```

Network interception, replay, and packet capture must only be used on systems the operator is authorized to test.

## Product invariants

- Data and storage remain under the user's control. Core workflows use local deterministic processing and do not require an official cloud account.
- `Task` definitions and immutable `Run` facts are separate. Past results retain the configuration snapshot that produced them.
- Network, parsing, cleaning, database, capture, export, and plugin work never runs on the GUI event loop.
- Cookie, Authorization, tokens, request bodies, and private paths are redacted at log, diagnostic, export, and plugin boundaries by default.
- The six visual presets share one information architecture and one set of page objects. Theme changes only update semantic tokens and rendering.
- Liquid Glass is an enhancement layer. Solid fallback, Reduce Motion, and adaptive-quality modes preserve every business function.

## Implemented workspaces

- Dashboard with local metrics, recent runs, schedules, and health indicators
- Capture Tasks with HTTP configuration, bounded multi-URL async fetching on the modern runtime with a bounded thread compatibility fallback, global/per-host concurrency limits, adaptive low-end budgets, HTML/JSON/XML parsing, CSS/XPath/JSON-path fields, cleaning, validation, preview, pause/resume/cancellation, run queue, and history
- Search Center with SQLite FTS5
- Data Management with virtualized paging, lineage, CSV/JSON/JSONL/XLSX streaming export, and Dataset Revision creation
- Network Analysis with Browser Capture, tshark/dumpcap packet capture, process attribution, ring-buffer backpressure, dropped-event accounting, HAR analytics, Waterfall, Request Replay, TLS Inspector, DNS Analyzer, streaming PCAP/PCAPNG ingestion, native capture fallback, bounded TCP stream reassembly, flow-quality signals, and a native 87-protocol structured metadata catalog backed by dynamic external protocol/field discovery when the optional dissector runtime is present
- Professional Suite with Packet Intelligence, Intercept & Debug, MITM Proxy, Extraction Lab, an independent Traffic Forensics workbench for passive host/error/latency/large-transfer/sensitive-plaintext triage, and bounded forensic JSON export that does not copy credential values into findings
- V6.1 Unified Network Core with Project/Source ownership, deterministic Flow and HTTP request/response identities, DNS/TLS/WebSocket projections, and atomic dual-write compatibility with legacy capture events
- V6.2 Network Capture Enrichment with bounded content-addressed Body References, HAR request/response body persistence, browser WebSocket frame capture, richer TLS/server metadata, and tshark DNS/TLS/endpoint normalization
- V6.2.1 Autopilot Learning integration with a bounded local ExperienceStore, deterministic strategy priors, selector recovery ranking, failure classification, explicit feedback, and redacted JSONL export; the feature remains advisory and does not replace deterministic execution.
- V6.3 Replay + API Map with normalized HTTP Exchange inventory, deterministic endpoint signatures, bounded JSON schema inference, verified Body Ref reconstruction, Secret-safe replay drafts, side-effect confirmation, structural response diff, replay history, and atomic API Map snapshots.
- V6.4 Dataset + Data Lineage with first-class Dataset registry, immutable revisions, hidden build states, streaming Run materialization, stable logical record identity, bounded online schema inference, lineage graph persistence, and crash-safe revision recovery.
- V6.5 Workflow Engine integration with Dataset Revision → Workflow → Dataset Revision execution, durable checkpoints, deterministic/idempotent output identities, node-level execution metrics, cancellation/resume, semantic workflow-definition guards, and end-to-end lineage.
- Workflow / Visual Data Pipeline 2.0 with normal and failure edges
- Automation with timezone-aware interval/daily/weekly scheduling
- Advanced Platform with Smart Execution Planner, Website Intelligence Map, API Map, Compatibility, Performance, Security Center, and Universal Database Adapter diagnostics
- Intelligence Studio with SmartPath 2.0/data-source discovery, Explainable Web Intelligence Blueprint (decision trace, cost/stability estimates, fallback chain), **Autopilot deterministic learning** (local privacy-preserving ExperienceStore, strategy priors, selector recovery ranking, failure classification, redacted future-training JSONL), Selector Studio/self-healing, zero-copy Network → HTTP → Workflow Context Bridge, HTTP Request Builder + assertions/code generation, GraphQL/WebSocket/SSE inspection, Browser Recorder 2.0, Data Quality/Schema Studio, Workflow Debugger + scoped variables, `arenyxa.workflow/v1` compatibility workflow schema (retained in v6.7), offline Compatibility Lab, Secrets Vault, project Python environments, Browser Profiles, checksum-verified Workflow Marketplace, opt-in distributed Headless Workers, and Live Run/Activity Center
- Data Visualization Studio with line, bar, pie, heatmap, timeline, and offline coordinate-map rendering
- Data Version Control with record/field/schema diff and non-destructive rollback service
- Plugin discovery and subprocess sandbox with permissions, timeout, output, and Windows Job Object memory budgets
- X-inspired minimal startup transition using the Arenyxa icon: instant first paint, no progress-bar theater, initialization continues behind the clean launch surface, and a paint-only in-window handoff continuously enlarges the centered mark while a center-origin circular mask reveals one prepared MainWindow frame; the diagonal-derived mask, shared launch geometry, OS/user Reduce Motion path, adaptive small-logical-screen minimums, and safe/legacy/reduced-visual bypasses cover portrait, ultrawide, multi-monitor, maximized, and high-DPI launches
- Hardened project-scoped Developer Terminal with Arenyxa/Direct/PowerShell/CMD/Python modes, real-time streaming, cancellation, bounded output, session cwd/env/history, read-only SQL, structured logs, diagnostics, DNS/TCP/TLS/interface/socket probes, service/protocol lookup, offline packet summary/frame/statistics commands, native hex-frame protocol decoding, personalization, ten locales/RTL, and About/build information
- Windows shell integration with live top-bar run/capture/advanced-operation progress, taskbar progress states, system-tray Blueprint/Autopilot/Compatibility quick actions, Intelligence Studio shortcuts, and command-palette actions
- Startup self-healing health check and automatic Repair Center with crash/settings/database/plugin/file-integrity recovery and a local recovery payload
- `.arenyxa` portable project package with legacy `.arenyxa` open compatibility, Browser Profiles, Regression Lab, Workflow Marketplace client, and Headless Server with token auth/RBAC

## Protocol intelligence and deep capture

Arenyxa uses a two-layer packet-analysis architecture. The dependency-free native layer streams classic PCAP and PCAPNG files and provides bounded structured metadata decoding for 87 high-value link, network, transport, routing, tunnel, security, application, database, messaging, remote-access, and industrial protocols. The native path covers common Ethernet, VLAN/MPLS, Loopback, PPP, Radiotap/802.11, IPv4/IPv6, TCP/UDP/SCTP/DCCP, IPsec/GRE, DNS-family protocols, DHCP, TLS, HTTP, QUIC, routing protocols, overlays, RPC/NFS, database handshakes, real-time media, and industrial-control traffic. TCP directions use bounded reassembly for application identification across segment boundaries while retaining retransmission, out-of-order, zero-window, reset, and gap signals.

When the optional external dissector runtime is installed, Arenyxa discovers its protocol and field registries dynamically instead of hard-coding a fixed long-tail list. That external layer provides the broadest available protocol tree, display-filter, field extraction, follow-stream, object export, capture conversion/merge, and statistics coverage, while the native layer remains available as a deterministic fallback. No implementation can truthfully guarantee decoding every proprietary, encrypted, malformed, future, or undocumented protocol; unsupported encrypted payloads remain opaque unless the required keys or an authorized decryption path are available.

Large offline imports use streaming packet/event iterators and batched persistence rather than materializing the entire capture in memory. Native readers enforce per-packet/block/packet-count budgets, and protocol decoders bound layer depth, VLAN/MPLS stacks, IPv6 extensions, compressed DNS names, TCP reassembly state, text fields, and high-cardinality statistics.

## v7.0 integrated release scope

The cumulative Phase 1–12 v7.0 source includes an **Enterprise Server / Worker** foundation without forking the Core Runtime: a durable SQLite queue, Worker Ed25519 identity/challenge proof, protocol N/N-1 negotiation, leases/checkpoints/idempotency, Worker loss recovery, non-idempotent side-effect fencing, drain/revoke/health, a TLS-only Worker API, Worker execution through the same `RunOrchestrator`, and a signed encrypted-Vault authority migration bundle. Enterprise Server administration remains fail-closed and native multi-machine/Windows Service validation is still a release gate.

Phase 12 adds explicit migration policies, backup-first upgrade transactions, verified control-file and SQLite rollback, Stable/Beta/Developer/Enterprise release channels, LTS/deprecation policy, compatibility matrix and an independent trust/IAM/protocol review checklist. The internal runtime/plugin compatibility identity remains `6.8.0` until a deliberate compatibility promotion; the v7.0 product release is not itself an API/protocol compatibility bump.

Root Developer workstations use an Owner-Authority-provisioned, DPAPI-protected workstation binding rather than a mutable preference. A verified Root workstation starts each launch from default application preferences and reopens the independent first-run Welcome Center while preserving Projects, databases, Captures and Enterprise Vault data. Its runtime-only `platform.root` authority unlocks Arenyxa Personal/Developer technical surfaces without converting Root Developer into a customer Enterprise data key.

Enterprise administration is scroll-backed and uses responsive action grids so long action rows reflow instead of colliding with card borders at narrow widths/high DPI. The Desktop also exposes authorized Phase-11 distributed queue/Worker/Job views, while the actual Enterprise Server and Worker continue to run as independent processes over the shared Core Runtime.

## Quick start

The current dependency model is capability-based. For headless core development, `python -m pip install -e .` installs only the core runtime (`tzdata`, `cryptography`, and `httpx`). Add extras such as `desktop`, `analysis`, `browser`, `database`, `capture`, `server`, or `telemetry` only when that capability is required. `requirements.txt` mirrors the minimal core; `requirements-full.txt` is the convenience bundle for a complete local workstation.

On Windows PowerShell, the product bootstrap intentionally provisions the full desktop development workstation:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\bootstrap.ps1
.\scripts\run.ps1
```

The bootstrap script creates `.venv`, installs the application and test toolchain, and does not change the system Python installation.

### Windows 7 SP1 x64 / Legacy Enterprise

The Legacy lane is intentionally isolated from the modern runtime. It requires **Windows 7 SP1 x64**, **CPython 3.8.x x64**, and the Windows 7 loader capabilities supplied by **KB2533623 or a superseding cumulative update**. The bootstrap probes `SetDefaultDllDirectories` directly instead of trusting hotfix inventory alone. It uses PySide2/Qt5 and conservative graphics defaults.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\bootstrap-win7.ps1
.\scripts\test-win7.ps1
.\scripts\run-win7.ps1
```

To produce the Legacy portable build:

```powershell
.\scripts\build-win7.ps1
```

`packaging\installer_win7.iss` is the dedicated Inno Setup profile. The Win7 build disables Browser Recorder/Playwright execution because current bundled browser runtimes are not part of the Legacy compatibility contract; ordinary HTTP collection and the rest of the shared core remain available.

Optional capabilities:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[desktop,analysis,browser,server,database,capture]"
.\.venv\Scripts\python.exe -m playwright install chromium
```

System packet capture requires a compatible packet-analysis runtime and packet-capture driver. Arenyxa requests the driver capability only for system capture; Browser Capture, HAR, and normal data collection do not require administrator privileges. HTTPS system packets remain encrypted unless metadata is visible through the protocol handshake.


### Developer validation commands

The built-in Developer Terminal provides two protected validation commands. They are available only after Developer Mode is enabled and the current risk agreement plus test waiver are accepted.

- `test-all` runs isolated local validation across the major data, workflow, scheduler, capture, export, HTTP loopback, runner, terminal-boundary, and Studio service paths.
- `stress-test quick|standard|extreme` performs the bounded `local-persistence-mixed-v2` concurrency ramp in temporary local data and reports the highest observed stable worker level plus the first detected instability. Its memory probe runs before the timed ramp so Python allocation tracing cannot manufacture multi-thread contention inside the score; an already-active external tracer is rejected instead of silently corrupting the measurement. This lane represents SQLite/FTS, atomic-file, JSON, and selector work rather than public-network HTTP throughput. It does not intentionally exhaust system memory, fill the disk, or access public targets.

## Tests and release build

```powershell
.\scripts\test.ps1
.\scripts\build.ps1
```

The release script performs compile, unit/integration, import, offscreen Qt smoke, and PyInstaller build gates. If Inno Setup 6 or 7 is installed, it also creates a Windows installer with Start Menu/Desktop shortcuts and an uninstaller.
The build also generates a local installation-integrity manifest and compressed recovery payload used by the automatic Repair Center.

Detailed instructions are in [LOCAL_BUILD_zh-CN.md](docs/LOCAL_BUILD_zh-CN.md) and [WINDOWS_INSTALLER_zh-CN.md](docs/WINDOWS_INSTALLER_zh-CN.md).
The v7.0 stable promotion, release-identity separation, and remaining native/operator gates are documented in [V7.0_STABLE_RELEASE_2026-08-14.md](docs/V7.0_STABLE_RELEASE_2026-08-14.md).
The v6.7 startup-motion release delta is documented in [V6.7_STARTUP_MOTION_RELEASE_2026-08-11.md](docs/V6.7_STARTUP_MOTION_RELEASE_2026-08-11.md).

The v6.8 adaptive-concurrency beta delta is documented in [V6.8_BETA_ADAPTIVE_CONCURRENCY_2026-08-11.md](docs/V6.8_BETA_ADAPTIVE_CONCURRENCY_2026-08-11.md). The stable promotion, startup-motion polish, and final reliability re-audit are documented in [V6.8_STABLE_RELEASE_2026-08-11.md](docs/V6.8_STABLE_RELEASE_2026-08-11.md). The performance-diagnostic correction and center-mask startup handoff are documented in [V6.8_STABLE_PERFORMANCE_STARTUP_CONTINUITY_HOTFIX_2026-08-11.md](docs/V6.8_STABLE_PERFORMANCE_STARTUP_CONTINUITY_HOTFIX_2026-08-11.md). The final hot-path, Capture/Repair/Workflow, mixed-DPI, accessibility, and delivery freeze is documented in [V6.8_STABLE_FINAL_PERFORMANCE_STABILITY_COMPATIBILITY_FREEZE_2026-08-11.md](docs/V6.8_STABLE_FINAL_PERFORMANCE_STABILITY_COMPATIBILITY_FREEZE_2026-08-11.md).

The original Windows 7 compatibility design is documented in [V6.6.1_WINDOWS7_LEGACY_COMPATIBILITY_6X_REVIEW_2026-08-09.md](docs/V6.6.1_WINDOWS7_LEGACY_COMPATIBILITY_6X_REVIEW_2026-08-09.md). The independent beta2 follow-up audit is documented in [V6.6BETA2_INDEPENDENT_COMPATIBILITY_REAUDIT_2026-08-10.md](docs/V6.6BETA2_INDEPENDENT_COMPATIBILITY_REAUDIT_2026-08-10.md). The beta2 lifecycle/repair/capture deep review is documented in [V6.6BETA2_DEEP_CODE_REVIEW_2026-08-10.md](docs/V6.6BETA2_DEEP_CODE_REVIEW_2026-08-10.md). The stable promotion and Windows packaging closure are documented in [V6.6_STABLE_RELEASE_2026-08-10.md](docs/V6.6_STABLE_RELEASE_2026-08-10.md).

PDF 基线解析、完整需求注册表、架构、模块/UI 树、追踪和验证证据分别位于 `docs/BASELINE_ANALYSIS.md`、`docs/SOFTWARE_REQUIREMENTS_SPECIFICATION.md`、`docs/ARCHITECTURE.md`、`docs/FUNCTION_MODULE_TREE.md`、`docs/UI_COMPONENT_TREE.md`、`docs/REQUIREMENTS_TRACEABILITY.md` 与 `docs/QA_VERIFICATION_REPORT.md`。

## Repository map


`src/arenyxa/` is the public v8.1 application package. `src/arenyxa/` is intentionally retained as the internal compatibility implementation namespace so plugins, repair payloads and existing integrations are not broken by the brand migration.

```text
src/arenyxa/
  __main__.py         Public `python -m arenyxa` entry point
  app.py              Public desktop facade
  server.py           Public headless facade
src/arenyxa/
  domain/             Stable entities, state machines, errors, RBAC
  application/        Use cases, runner, scheduler, export, versioning, workflows
  infrastructure/     SQLite, HTTP, parsers, capture, server, plugins, adapters
  presentation/       Qt-compatible shell, pages, semantic themes, glass and motion
tests/                 Unit, integration, contract, security and offscreen UI tests
docs/                  Requirements, architecture, UI tree, roadmap and build guides
scripts/               Bootstrap, run, test, release and installer automation
```

## License

GPL-3.0-or-later.

## Product naming and attribution policy

Arenyxa uses its own capability names across the UI, source symbols, tests, reports, and release artefacts. Comparator-style product labels are not used as Arenyxa feature names. Optional external runtimes are referenced only where a real executable or package dependency must be identified for correct operation, and applicable third-party license or notice obligations must be preserved.
