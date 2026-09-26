# Arenyxa v0.1

Arenyxa is an open-source, Windows-first network analysis, traffic forensics, proxy debugging, data workflow, automation, and local security engineering platform.

**Arenyxa v0.1 is the first formal public release in the GitHub release version line.**

The project existed through a long internal engineering cycle before the public version line was reset. Historical labels such as v6.x, v7.x, v8.0, v8.1, and v8.2 are retained as engineering milestones and validation baselines. They are not the public semantic-version sequence going forward.

Public version: **v0.1**  
Package / distribution version: **0.1.0**  
Windows file version: **0.1.0.0**  
Internal engineering baseline: **v8.2.0**  
Runtime / plugin compatibility identity: **6.8.0**

See [VERSIONING.md](VERSIONING.md) for the complete version model.

## Download

The canonical download location is the latest GitHub Release:

https://github.com/Arenyxa/Arenyxa/releases/latest

Release assets are Windows installers or explicitly named release artifacts. GitHub-generated source archives are source code and are not Windows installers.

Project source:

https://github.com/Arenyxa/Arenyxa

Project websites:

https://arenyxa.pages.dev/

https://arenyxa.github.io/

## What Arenyxa provides

Arenyxa combines desktop workflows, a command-line control plane, server/worker execution, local data management, recovery tooling, and enterprise-oriented security boundaries in one codebase.

Core product areas include network capture and analysis, HTTP/browser/packet workflows, proxy and MITM debugging for authorized environments, API analysis, traffic forensics, protocol intelligence, data extraction, datasets and lineage, workflow automation, visualization, scheduling, plugins, terminal tooling, diagnostics, Repair Center, Enterprise identity/governance, Server/Worker execution, and SQLite/PostgreSQL storage boundaries.

The desktop application and CLI use shared application services rather than separate business-logic implementations. Security-sensitive capabilities are enforced by backend policy; hiding or showing a UI control is not treated as authorization.

Arenyxa is local-first. Core projects, settings, search indexes, datasets, captures, and diagnostics are designed to remain under the operator's control. Network-facing functions naturally contact the targets or infrastructure selected by the operator.

## Platform

The primary runtime targets modern Windows with Python 3.11–3.13 and PySide6.

A separate frozen compatibility lane exists for Windows 7 SP1 x64 with Python 3.8 and PySide2. That lane is maintained for compatibility and does not define the public release version independently.

Optional capabilities are installed by feature group so headless and development environments do not need the entire desktop stack.

## Quick start

On Windows PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\bootstrap.ps1
.\scripts\run.ps1
```

For an editable Python installation:

```powershell
python -m pip install -e ".[desktop,analysis,capture]"
arenyxa-gui
```

Additional optional groups include `browser`, `database`, `server`, `telemetry`, `crawler`, and `mcp`.

## Build and test

Run the release-blocking validation suite:

```powershell
.\scripts\test.ps1
```

Build the modern Windows package:

```powershell
.\scripts\build.ps1
```

The build pipeline validates the canonical public release identity before packaging. Modern installer output is expected to use the public name:

```text
Arenyxa_v0.1_Setup_x64.exe
```

The legacy Windows 7 package uses:

```text
Arenyxa_v0.1_Legacy_Win7_x64_Setup.exe
```

## Version model

Arenyxa deliberately separates three identities.

| Identity | Current value | Purpose |
| --- | --- | --- |
| Public release | `v0.1` | Version shown to GitHub users and in the application |
| Package / distribution | `0.1.0` | PEP 440, installer, attestation, and package metadata |
| Engineering baseline | `v8.2.0` | Internal development history and engineering provenance |
| Runtime / plugin compatibility | `6.8.0` | Compatibility contract; changes only through an explicit migration |

The internal engineering baseline must not be used as the public product version. Likewise, the public v0.1 reset does not reset database schema numbers, workflow schemas, Enterprise protocol versions, plugin APIs, or other machine compatibility identifiers.

Historical v6/v7/v8 reports remain in the repository because they contain useful engineering evidence. They should be read as internal milestone records. Any older GitHub Release artifacts carrying v8.x names are legacy development snapshots from before the public numbering policy was corrected; the public release line starts at v0.1.

## Architecture and safety boundaries

Arenyxa follows a layered architecture with domain, application, infrastructure, presentation, security, enterprise, and compatibility boundaries.

Long-running network, parsing, capture, export, database, plugin, and workflow work is kept off the GUI event loop. Durable operations are designed around bounded queues, explicit lifecycle states, cancellation, failure recovery, and auditability.

Secrets such as Authorization values, cookies, tokens, private paths, and credential-bearing payloads are redacted or constrained at log, diagnostic, export, and plugin boundaries where applicable.

Security-sensitive operations must be used only on systems, traffic, and infrastructure the operator owns or is authorized to test.

## Internationalization

Arenyxa supports runtime localization through `LanguageManager` and packaged locale catalogs. New high-visibility UI surfaces use semantic catalog keys instead of embedding user-facing language directly in page source.

Legacy pages are being migrated incrementally so compatibility behavior remains stable while hard-coded UI copy is removed.

## Repository layout

```text
src/arenyxa/
  domain/             entities, state machines, errors, permissions
  application/        use cases, orchestration, workflows, versioning
  infrastructure/     storage, HTTP, capture, server and adapters
  presentation/       desktop shell, pages, themes and localization
  enterprise/         enterprise identity, governance and distributed runtime
  security/           trust, hardware identity and security boundaries

legacy/win7/          frozen Windows 7 compatibility lane
scripts/              bootstrap, validation, build and release automation
packaging/            PyInstaller and Inno Setup definitions
tests/                regression, contract, security and platform tests
docs/                 architecture, engineering history and release evidence
```

## Release and engineering history

Public release history begins with **v0.1**.

Internal engineering milestone documents retain their original v6.x, v7.x, and v8.x identifiers for traceability. Their original technical claims and validation evidence are not rewritten into fake public releases.

See:

[VERSIONING.md](VERSIONING.md)

[Engineering Release History](docs/RELEASE_HISTORY.md)

[Architecture](docs/ARCHITECTURE.md)

[API Reference](docs/API_REFERENCE.md)

[Security Policy](SECURITY.md)

## License

Arenyxa is licensed under **GPL-3.0-or-later**. See [LICENSE](LICENSE).

Release signatures and integrity metadata verify provenance and installed content. They do not replace the open-source license, require online activation, or convert the application into a hardware-bound product.
