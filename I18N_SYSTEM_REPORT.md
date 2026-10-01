# Arenyxa v0.1 I18N System Report

## Implementation

The existing runtime translation dictionaries and `LanguageManager` remain compatible with legacy pages. Packaged JSON catalogs in `src/arenyxa/locale/` continue to merge over compatibility dictionaries at startup.

Catalog-backed semantic UI keys are now supported directly by `LanguageManager`. Shared `PageHeader` and `SectionCard` widgets can bind semantic translation keys, and combo-box items can bind per-item keys. This allows locale changes to re-render from stable catalog identifiers rather than depending on Chinese/English literal phrase matching.

Packaged catalogs currently include:

- `zh_CN.json`
- `en_US.json`
- `ja_JP.json`
- `fr_FR.json`
- `de_DE.json`

The language picker continues to expose the compatibility locales in addition to the packaged catalogs.

## Migrated surfaces

The following high-visibility surfaces no longer embed Chinese user-facing copy directly in their page source:

- Welcome Center / work-mode selection
- Personalization / visual presets / motion / interface scaling
- Settings / resource governance / diagnostics / Developer and Root authorization prompts
- About / release provenance / integrity verification / Developer Terms
- Personalization theme-card metadata
- Network Analysis / capture controls / Replay / TLS / DNS / Professional Analysis / PCAP and process-monitor messaging
- Studio tooling / Project Python / Marketplace / Compatibility / Portability / Autopilot
- Dashboard / metrics / task queue / schedules / local-index statistics
- Task Center / Simple Mode / guided workflows / runtime-capability guidance
- Tasks / Task Editor / preflight resource messaging / task and run status display
- Data / Search / Dataset Revision / streaming export
- Studio Intelligence / SmartPath / Blueprint / Selector / HTTP / Protocol / Quality / Recorder / Debugger
- Data Visualization Studio / chart assets / PNG export
- Terminal & Packet Console / Logs / mode selection
- Advanced Platform / Plugins / analysis tabs / database adapter
- Automation Center / Flow Designer / Visual Graph / Execution Inspector
- Enterprise Identity / RBAC / Vault / Enrollment / Coordinator / Governance / Distributed Operations
- Terminal execution / persistent Shell workspace / builtins / high-risk command confirmations
- Main Window shell / navigation / command palette / startup recovery / Root Authority challenge
- Root Developer / Root Owner break-glass and startup authentication gates

Their user-facing copy is now sourced from semantic catalog keys under stable page/domain namespaces such as `welcome.*`, `personalization.*`, `settings.*`, `network.*`, `studio.*`, `studio_intelligence.*`, `dashboard.*`, `task_center.*`, `tasks.*`, `data.*`, `visualization.*`, `tools_*.*`, `tools_terminal.*`, `enterprise.*`, `shell.*`, and `root_gate.*`.

## Regression protection

`tests/test_i18n_semantic_keys.py` enforces:

- automatic discovery of every Python module under `src/arenyxa/presentation/pages/`; no page may introduce direct CJK UI literals;
- automatic scanning of presentation runtime modules outside `pages/`, with an explicit allowlist only for translation/resource modules such as the language catalogs, Repair Center locale resources, centralized product copy, and bilingual theme source labels;
- no CJK UI literals are reintroduced in the migrated semantic-key source files;
- every referenced semantic key exists in each packaged locale catalog;
- semantic widget keys re-render correctly when the active locale changes.

This means newly added presentation pages are covered by the hard-code gate automatically and do not need to be manually added to a file list before CJK regressions can be detected.

## Remaining migration work

The public release is v0.1; the preserved internal engineering baseline is v8.2.0. Legacy business pages still contain compatibility phrase mappings and hard-coded UI text that are translated through the existing `translate_tree` compatibility path. The next migration targets are any residual operational pages not already catalog-backed. Migration should continue incrementally by page and should not internationalize machine identifiers, database keys, protocol/event codes, permission identifiers, or persisted enum values.
