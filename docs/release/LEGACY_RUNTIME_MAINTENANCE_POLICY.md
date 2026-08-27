# Arenyxa Legacy Runtime Maintenance Policy

Arenyxa has two deliberately different support lanes.

- **Modern** — Python 3.11–3.13 + PySide6. Active feature development and the complete supported feature set.
- **Legacy Enterprise** — Python 3.8 + PySide2 for managed/Windows 7 compatibility. Feature-frozen; receives critical security, data-integrity, repair, and compatibility fixes only.

New Modern features are **not required** to be backported to the Legacy lane. Legacy-specific shims must stay behind compatibility boundaries (`platform_compat.py`, `qt_compat.py`, or narrowly scoped adapters) and must not constrain new core-runtime syntax or architecture beyond the existing Python 3.8 source-grammar publication gate.

This policy bounds the maintenance cost of the compatibility lane without abruptly removing deployments that still depend on it.
