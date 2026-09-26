# Arenyxa v0.1 — Current Capability Manifest

## Release identity

- Public display version: `v0.1`
- Package/distribution version: `0.1.0`
- Windows file/product version: `0.1.0.0`
- Internal engineering baseline: `v8.2.0`
- Completed internal engineering phase: **Phase 8**
- Compatibility identity: `6.8.0` (intentionally preserved)
- Primary runtime lane: Windows-first Python 3.11–3.13 / PySide6
- Frozen compatibility lane: Windows 7 SP1 x64 / Python 3.8 / PySide2

The v6/v7/v8 identifiers referenced below are internal engineering milestones retained for technical provenance. GitHub public release numbering starts at v0.1.

## Preserved platform capabilities

The v0.1 public tree carries forward the internally validated v8.2 engineering baseline, including:

- Desktop GUI and complete developer CLI
- Application, Traffic, and Enterprise control planes
- HTTP/Browser/packet capture and protocol intelligence
- Proxy Suite, authorized MITM, replay, API analysis, and Traffic Forensics
- Extraction, crawler, workflow, automation, data lineage, search, and visualization
- Security Kernel, Zero Trust, Root/Developer authority, audit, and release provenance
- Enterprise identity, enrollment, governance, Server/Worker runtime, and durable jobs
- SQLite/PostgreSQL storage boundaries and distributed lease/fencing behavior
- Recovery Center, Safe Mode, source repair, runtime supervision, and diagnostics
- Windows desktop/service integration, packaging, and the isolated Win7 compatibility lane
- Semantic i18n catalogs plus the compatibility translation path

No valid user-facing capability is intentionally removed by the public-version reset.

## Reliability and survivability

Arenyxa includes bounded survivability states:

- `normal`
- `degraded`
- `resource_pressure`
- `read_only`
- `recovering`
- `safe_mode`

Resource pressure, runtime supervision, telemetry, queue admission, logging fallback, and recovery remain bounded and observable. Critical disk pressure can enter read-only behavior; diagnostics and audit paths remain available according to their existing safety contracts.

## Compatibility boundary

The following are deliberately **not** reset to 0.1:

- Runtime/plugin compatibility: `6.8.0`
- Enterprise protocol: current `2`, minimum `1`
- Workflow schema: `arenyxa.workflow/v1`
- Settings and persisted-data schema versions
- Database migration identifiers
- Security/audit event identifiers

These are interoperability or persistence contracts rather than product marketing versions.

## Validation boundary

CI covers static quality, architecture, workflow contracts, unit/integration regressions, Windows desktop contracts, dependency/SBOM checks, and PostgreSQL stress gates where configured.

External/native claims remain evidence-driven. Native Windows drivers, TPM/CNG, DPAPI, SCM behavior, optional TShark parity, and real multi-host environments are reported as `NOT EXECUTED` when their prerequisites are unavailable.

See [VERSIONING.md](VERSIONING.md) for the version policy and [docs/RELEASE_HISTORY.md](docs/RELEASE_HISTORY.md) for preserved internal engineering history.
