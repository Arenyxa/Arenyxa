---
status: current
owner: documentation
last_reviewed: 2026-10-28
---

# Arenyxa documentation index

| I want to… | Read | Lifecycle |
| --- | --- | --- |
| Understand the product and start it | [README](../README.md) | Current |
| Check publication status and limitations | [Release status](release/RELEASE_STATUS.md) | Current |
| Install on Windows | [Windows installer guide](WINDOWS_INSTALLER_zh-CN.md) | Current |
| Build from source | [Local build guide](LOCAL_BUILD_zh-CN.md) | Current |
| Integrate against command/API surfaces | [API reference](API_REFERENCE.md) | Stable reference; verify optional adapters |
| Understand system design | [Architecture](ARCHITECTURE.md), [module tree](FUNCTION_MODULE_TREE.md), [UI component tree](UI_COMPONENT_TREE.md) | Stable reference |
| Navigate source code | [Code navigation](architecture/CODE_NAVIGATION.md) | Developer reference |
| Review architecture decisions | [ADR index](architecture/adr/INDEX.md) | Append-only; decisions may be superseded |
| Run tests and quality gates | [Testing guide](TESTING.md), [CI quality matrix](CI_QUALITY_MATRIX.md) | Current |
| Understand security boundaries | [Security docs](SECURITY.md), [root SECURITY.md](../SECURITY.md) | Current |
| Understand version/build/compatibility identities | [Version policy](../VERSIONING.md), [release provenance](RELEASE_PROVENANCE_AND_ANTI_TAMPER.md) | Current |
| Read release milestones | [Release history](release/history/RELEASE_HISTORY.md) | Timeline, not current verdict |
| Find old audits, baselines, fixes, and evidence | [Historical report index](internal/REPORT_INDEX.md) | Historical |
| Review previous roadmap snapshots | [Roadmap archive index](roadmap/INDEX.md) | Historical |
| Read current release identity and machine-generated evidence | [Metadata index](../metadata/README.md) | Machine-readable contracts and gate results |

## Lifecycle rules

- `stable`: architecture/API contracts; change deliberately.
- `current`: describes the current public release or supported workflow.
- `draft`: proposal not adopted.
- `historical`: preserved evidence, not a source of current truth.
- Root Markdown allowlist: `README.md`, `SECURITY.md`, `VERSIONING.md`, and optional `CHANGELOG.md`.
- Machine-readable gate outputs remain at their current paths until consumers, tests, workflows, and manifest generation can be updated together.
- Historical report blobs are not rewritten to add front matter; lifecycle state and SHA-256 remain in indexes/manifests.
