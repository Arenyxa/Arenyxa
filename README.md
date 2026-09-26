# Arenyxa v0.1

**Arenyxa v0.1** is the first formal GitHub release line for Arenyxa.

Arenyxa is a Windows-first, desktop-first network analysis, traffic inspection, automation, data, recovery, and enterprise-runtime platform with a complete CLI and headless Server/Worker capability.

> **Versioning note**
>
> Public release: **v0.1**  
> Package/distribution version: **0.1.0**  
> Windows file version: **0.1.0.0**  
> Internal engineering baseline: `v8.2.0`  
> Runtime/plugin compatibility identity: `6.8.0`
>
> Historical labels such as `v6.x`, `v7.x`, `v8.0`, `v8.1`, and `v8.2` are retained as internal engineering milestones and provenance. They were not prior GitHub public releases. See [VERSIONING.md](VERSIONING.md).

## Download and official links

- Latest formal release: https://github.com/Arenyxa/Arenyxa/releases/latest
- Source repository: https://github.com/Arenyxa/Arenyxa
- Flagship experience: https://arenyxa.pages.dev/
- Official introduction: https://arenyxa.github.io/

GitHub's automatically generated source archives contain source code. Windows installer assets, when published, are attached to the GitHub release.

## What Arenyxa includes

Arenyxa combines several normally separate workflows into one local-first platform:

- **Capture & traffic analysis** — Browser/HAR capture, packet capture, PCAP/PCAPNG ingestion, HTTP exchange analysis, DNS/TLS inspection, protocol metadata, TCP reassembly, flow-quality signals, and optional external dissector integration.
- **Proxy & interception** — Proxy Suite, authorized MITM workflows, replay, request inspection, traffic history, and forensic views.
- **API & web analysis** — API Map, replay drafts, request building, extraction, crawler workflows, selector tooling, GraphQL/WebSocket/SSE inspection, and browser recording.
- **Data & search** — SQLite/FTS5 search, Dataset revisions, lineage, CSV/JSON/JSONL/XLSX export, schema analysis, and visualization.
- **Workflow & automation** — persistent workflows, deterministic execution, checkpoints, cancellation/resume, scheduling, and automation surfaces.
- **Security & trust** — Security Kernel, Zero Trust boundaries, signed plugin trust, Root/Developer authority flows, audit, local secret handling, and release provenance verification.
- **Enterprise runtime** — Enterprise identity/governance, Server/Worker operation, durable distributed jobs, leases, fencing, SQLite/PostgreSQL storage boundaries, and fleet operations.
- **Reliability & recovery** — Health checks, Safe Mode, Repair Center, source repair payloads, runtime supervision, survivability states, bounded telemetry, and failure drills.
- **Desktop experience** — Qt desktop shell, adaptive motion, Liquid Glass fallback behavior, high-DPI handling, accessibility options, personalization, multilingual UI, taskbar/tray integration, and command palette.

## Architecture

Arenyxa keeps presentation, application services, domain contracts, and infrastructure adapters separated.

```text
src/arenyxa/
  domain/             Core entities, state machines, errors, permissions
  application/        Use cases, workflows, scheduling, control planes
  infrastructure/     Storage, HTTP, capture, services, operating-system adapters
  enterprise/         Enterprise identity, queue, Server/Worker and governance
  security/           Trust, audit, key protection and authority boundaries
  presentation/       Qt shell, pages, i18n, themes and motion
```

Major runtime boundaries include:

- Application Control Plane
- Traffic Control Plane
- Enterprise Control Plane
- Security Kernel
- Job System
- Recovery / Health
- SQLite and PostgreSQL storage backends
- Windows desktop/service runtime

The GUI is a presentation surface, not an authorization boundary. Hiding or showing a control never grants a backend capability.

## Version model

Arenyxa intentionally separates three version domains:

| Domain | Current identity | Meaning |
|---|---:|---|
| Public product | **v0.1** | GitHub release and user-facing product version |
| Package/distribution | **0.1.0** | Python/PEP 440 and release artifact metadata |
| Internal engineering | **v8.2.0** | Historical development baseline retained for engineering provenance |
| Runtime/plugin compatibility | **6.8.0** | Compatibility contract; not a product release version |
| Enterprise protocol | **2 / minimum 1** | Server/Worker protocol negotiation |
| Workflow schema | **arenyxa.workflow/v1** | Persisted workflow format |

Internal milestone numbers are not reset because they remain useful for audit and regression history. Compatibility/schema/protocol numbers are also not reset because they affect persisted or interoperable behavior.

## Quick start

### Modern Windows / source development

Requirements:

- Python 3.11–3.13
- Windows 10/11 for the primary desktop runtime
- Optional external tools only for capabilities that require them

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\bootstrap.ps1
.\scripts\run.ps1
```

The bootstrap creates a project-local virtual environment and does not replace the system Python installation.

### Optional capability installation

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[desktop,analysis,browser,server,database,capture]"
.\.venv\Scripts\python.exe -m playwright install chromium
```

The base package stays modular. Desktop, browser, database, capture, analysis, server, and telemetry dependencies can be installed only when needed.

### Windows 7 Legacy lane

A frozen compatibility lane remains for Windows 7 SP1 x64 using Python 3.8 and PySide2.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\bootstrap-win7.ps1
.\scripts\test-win7.ps1
.\scripts\run-win7.ps1
```

This lane is compatibility-focused and does not receive every modern browser/runtime capability.

## CLI examples

```powershell
arenyxa proxy status
arenyxa proxy history --page 1 --page-size 100
arenyxa proxy sessions
arenyxa tls status
arenyxa api analyze --limit 10000
arenyxa analyze traffic --limit 10000
arenyxa enterprise status
arenyxa recovery check
arenyxa resilience status
arenyxa resilience performance
```

## Build and validation

```powershell
.\scripts\test.ps1
.\scripts\build.ps1
```

The release path validates the canonical public version identity before packaging. The modern installer is named from the public release line, for example:

```text
Arenyxa_v0.1_Setup_x64.exe
```

The Legacy installer uses:

```text
Arenyxa_v0.1_Legacy_Win7_x64_Setup.exe
```

The repository keeps historical v6/v7/v8 validation artifacts for engineering provenance, but current packaging and GitHub publication use only the public v0.1 identity.

## Data, privacy, and trust boundaries

Arenyxa is local-first:

- Core settings, databases, search indexes, projects, captures, and deterministic analysis remain local by default.
- Network features access the network only when their function requires it.
- Cookies, Authorization values, tokens, secrets, and private paths are redacted at logging, diagnostics, export, and plugin boundaries where applicable.
- Release signatures verify provenance and integrity; they are not license activation or hardware binding.
- Source builds remain modifiable under the project license.

## Authorized-use requirement

Packet capture, interception, replay, scanning, proxying, and security-analysis features must only be used on systems and networks the operator is authorized to test or administer.

## Documentation

Start with:

- [VERSIONING.md](VERSIONING.md) — public vs internal vs compatibility versions
- [CODE_NAVIGATION.md](CODE_NAVIGATION.md) — engineering navigation and modification boundaries
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — architecture
- [docs/RELEASE_HISTORY.md](docs/RELEASE_HISTORY.md) — preserved internal engineering history
- [CURRENT_CAPABILITY_MANIFEST.md](CURRENT_CAPABILITY_MANIFEST.md) — current capability boundary
- [SECURITY.md](SECURITY.md) — security policy
- [docs/LOCAL_BUILD_zh-CN.md](docs/LOCAL_BUILD_zh-CN.md) — local Windows build guide
- [docs/WINDOWS_INSTALLER_zh-CN.md](docs/WINDOWS_INSTALLER_zh-CN.md) — installer guide

## Release certification boundary

Automated tests and CI cannot substitute for every external environment.

Native Windows/Npcap/ETW/WFP/DPAPI/TPM-CNG/SCM validation, real PostgreSQL multi-host stress, optional external protocol-differential tests, and physical hardware ceremonies must be reported as `NOT EXECUTED` when the required environment is not available. Arenyxa's release evidence is intended to distinguish verified results from unexecuted external gates rather than manufacture a pass.

## License

GPL-3.0-or-later.
