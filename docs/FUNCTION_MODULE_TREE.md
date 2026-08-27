# Arenyxa V6.0 功能模块树

```text
Arenyxa V6.0
├─ Application Shell
│  ├─ First-run / single instance / crash marker / safe mode
│  ├─ MainWindow / Command Palette / global status
│  ├─ Theme / Locale / DPI / RTL / accessibility
│  └─ Safe shutdown / diagnostics / build information
├─ Collection Core
│  ├─ Task editor and versioned Task snapshot
│  ├─ RequestSpec: URL / method / query / headers / cookie / body / TLS / proxy
│  ├─ HTTP Fetcher / optional Playwright Fetcher
│  ├─ HTML / JSON / XML Parser Registry
│  ├─ CSS / XPath / JSON-path Field Extractor
│  ├─ Cleaner / Validator / Deduplicator
│  ├─ PreviewRun / Run Orchestrator / Queue / Cancel / Pause
│  └─ Scheduler / retry / timeout / rate and concurrency policy
├─ Data Platform
│  ├─ SQLite repositories / migration / Unit of Work
│  ├─ Result paging / provenance / retention
│  ├─ FTS5 local search
│  ├─ CSV / JSON / JSONL / XLSX export
│  ├─ Dataset Revision / field and schema diff / rollback
│  ├─ Universal Database Adapter
│  └─ Visualization Studio
├─ Network Domain
│  ├─ Capture Controller / bounded queue / dropped accounting
│  ├─ Browser Capture / DOM snapshot / HAR
│  ├─ tshark metadata / dumpcap pcapng chunks / process attribution
│  ├─ Native PCAP/PCAPNG streaming reader / dependency-free fallback
│  ├─ Native Protocol Intelligence / 87 structured protocol families
│  ├─ Bounded TCP directional reassembly / retransmission / gap / zero-window signals
│  ├─ Dynamic external protocol + field registry / arbitrary validated field extraction
│  ├─ Packet tree / follow-stream / protocol hierarchy / endpoints / conversations / expert stats
│  ├─ Unified Filter Engine
│  ├─ Traffic Timeline / Waterfall
│  ├─ Request Replay / compare / Workflow conversion contract
│  ├─ API Map / Website Intelligence Map
│  ├─ TLS Inspector / DNS Analyzer
│  └─ HAR import / analytics / comparison
├─ Advanced Analysis
│  ├─ Smart Execution Planner
│  ├─ Compatibility Analyzer
│  ├─ Performance Profiler
│  ├─ Security Configuration Center
│  └─ Regression Lab
├─ Runtime & Ecosystem
│  ├─ .arenyxa pack / validate / unpack
│  ├─ Headless Server / REST / auth / RBAC / audit model
│  ├─ Multi-user Workspace roles
│  ├─ Workflow / Pipeline 2.0 / failure ports
│  ├─ Workflow Marketplace client
│  ├─ Browser Profile Manager
│  ├─ Developer Terminal & Packet Console
│  │  ├─ Arenyxa / Direct / PowerShell / CMD / Python modes
│  │  ├─ Streaming output / Stop / stdin / timeout / output budget
│  │  ├─ Project-confined cwd / session env / redacted history
│  │  ├─ Task/Run/Capture/Event queries / read-only SQLite console
│  │  └─ DNS/TCP/TLS/interface/socket probes / protocol-service lookup / packet info-summary-frame-stats / native frame decode
│  └─ Plugin Manager / Permission Broker / Sandbox Worker
└─ Liquid Glass & Motion
   ├─ Semantic Theme and Material Tokens
   ├─ Surface / Glass / Elevated / Overlay / Solid Fallback
   ├─ Adaptive tint / rim refraction / pointer specular
   ├─ Spring Animator / Morph Geometry / Shared Intent
   ├─ Edge Flow / Live Data Motion / Panel state
   ├─ Motion Orchestrator / Microinteraction states
   └─ Refresh pacing / Frame Profiler / adaptive quality / Reduce Motion
```


## Competitive Edge / Web Intelligence expansion

```text
Web Intelligence Layer
├─ SmartPath 2.0 evidence
├─ Explainable Blueprint
│  ├─ decision trace
│  ├─ engine estimates: completeness / stability / resource efficiency
│  ├─ heuristic latency / RAM / request estimates
│  ├─ fallback chain
│  └─ risk flags + starter Workflow
├─ Context Bridge
│  ├─ NetworkEvent -> RequestSpec
│  ├─ RequestSpec -> generated code
│  └─ RequestSpec -> portable Workflow
├─ Workflow Portability
│  ├─ arenyxa.workflow/v1
│  ├─ deterministic canonical JSON
│  ├─ SHA-256 integrity
│  └─ inline-secret rejection / edge validation
├─ Compatibility Lab
│  ├─ deterministic offline fixtures
│  ├─ engine accuracy
│  ├─ data-source recall
│  └─ per-tag regression report
└─ Reliability Advisor
   ├─ rate-limit signal
   ├─ selector confidence drift
   ├─ schema drift
   ├─ data-quality drift
   └─ ordered recovery actions
```
