# Arenyxa v0.1

**Public source release v0.1.** Package identity is `0.1.0`, Windows file version is `0.1.0.0`, the retained engineering baseline is `v8.2.0`, and plugin/runtime compatibility remains `6.8.0`. The Windows distribution is **community unsigned**; source publication does not imply Authenticode signing or independent clean-machine installer qualification.

Arenyxa is a Windows-first network inspection, proxy debugging, data collection and automation application. Its source contains a Qt desktop shell, shared command/control services, local storage, headless server and Enterprise Worker surfaces. The capability descriptions below identify source scope; they do not certify every platform integration or deployment.

## Status and evidence

The current identity is recorded in [RELEASE_IDENTITY.json](RELEASE_IDENTITY.json), while [VERSIONING.md](VERSIONING.md) separates product, engineering, compatibility and schema versions. The current publication decision and validation scope are summarized in [docs/RELEASE_STATUS.md](docs/RELEASE_STATUS.md).

The v0.1 source tree passed the release regression/integrity work recorded for this cycle after the release owner approved the current application icon. Representative automated GUI flows and release-owner manual GUI acceptance are recorded separately. The optional 24-hour soak was explicitly deferred as non-blocking and is not reported as passed. Independent clean-machine install/upgrade/rollback/uninstall qualification is not claimed by this source publication. Historical engineering audits remain indexed in [docs/RELEASE_HISTORY.md](docs/RELEASE_HISTORY.md).

The modern lane targets Python 3.11–3.13 and PySide6. The frozen legacy lane targets Python 3.8/PySide2 on Windows 7 SP1 x64. **Legacy runtime, packaging and installation are NOT TESTED for this candidate.** Its matching version metadata is not a compatibility certification.

## Source capabilities

| Area | Implemented source boundary |
| --- | --- |
| Tasks and data | HTTP request configuration, extraction/parsing, cleaning, validation, Run history, export, immutable dataset revisions, lineage and workflows |
| Traffic | Capture adapters, protocol analysis, proxy/MITM, replay, HAR import/export, API analysis and traffic forensics; adapters depend on the selected runtime and permissions |
| Desktop | Qt shell, navigation, six theme presets, motion/Reduce Motion, diagnostics, Repair Center and command terminal |
| Runtime | Runner/scheduler/Job System ownership, cancellation, bounded queues, resource pressure, recovery, storage and diagnostic services |
| Server/Worker | Headless service plus authenticated Enterprise lease execution, fencing, SQLite/PostgreSQL backends and observability |
| Trust | Separate local/Developer/Enterprise/release trust domains, plugin capability controls and optional native Windows key protection |

Use capture, interception and replay only on systems you are authorized to inspect. Review [SECURITY.md](SECURITY.md) for trust boundaries and sensitive-data handling. Optional native capture, browser, database and telemetry dependencies are separate from basic product availability.

## Source setup and entry points

From a source checkout on a supported modern Windows x64 development machine:

```powershell
.\scripts\bootstrap.ps1 -SkipBrowserRuntime
.\.venv\Scripts\python.exe -B .\scripts\verify_release_identity.py
.\.venv\Scripts\python.exe -B -m arenyxa --version
.\.venv\Scripts\python.exe -B -m arenyxa --data-dir .\local-data
```

Bootstrap creates the local virtual environment and installs declared dependencies. Omit `-SkipBrowserRuntime` only when the optional browser runtime is needed. The last command starts the desktop and creates its explicitly selected data directory.

The installed console entry points are `arenyxa` / `arenyxa-cli` for commands, `arenyxa-gui` for the desktop, `arenyxa-server` for the headless server and `arenyxa-windows-service` for the Windows Service. Source command examples:

```powershell
.\.venv\Scripts\python.exe -B -m arenyxa.cli --data-dir .\local-data version
.\.venv\Scripts\python.exe -B -m arenyxa.cli --data-dir .\local-data help
```

Inspect command help and local authorization before enabling network capture, replay, a listening server or a service. A command's presence does not mean the necessary adapter, permission or trust provisioning is available.

## Tests and packaging

```powershell
.\.venv\Scripts\python.exe -B .\scripts\verify_release_identity.py
.\scripts\test.ps1
.\scripts\build.ps1 -RequireInno
```

The normal build invokes test and integrity gates, builds desktop/service payloads, and prepares the installer using Inno Setup. `-SkipTests` is a developer shortcut and must not be presented as release acceptance. Source/repair manifests must be regenerated after the final source changes, then verified against the packaged bytes.

Expected modern outputs are `dist/Arenyxa/Arenyxa.exe` and `dist/installer/Arenyxa_v0.1_Setup_x64.exe`. Their existence, hashes, signatures and successful clean-machine execution must be established from each build. See [Windows installer guide](docs/WINDOWS_INSTALLER_zh-CN.md) for installation, unsigned status, data retention and upgrade limitations.

The source repository is [Arenyxa/Arenyxa](https://github.com/Arenyxa/Arenyxa). Its [release inventory](https://github.com/Arenyxa/Arenyxa/releases) is separate from this local candidate's status; an automatically generated source archive is not a tested Windows installer.

## Repository map

- `src/arenyxa/`: modern Domain, Application, Infrastructure, Enterprise, Security and Presentation code.
- `legacy/win7/`: feature-frozen legacy source and compatibility lane.
- `tests/`: unit, integration, contract, security and offscreen UI checks; fixture identities remain historical.
- `packaging/` and `scripts/`: package metadata, build, test and validation tools.
- `docs/`: [architecture](docs/ARCHITECTURE.md), requirements, UI tree, historical evidence and build guidance.

## License and attribution

GPL-3.0-or-later. Arenyxa uses its own capability names. Optional third-party runtimes retain their package names where needed for installation or operation, and their applicable license/notice obligations remain in force.
