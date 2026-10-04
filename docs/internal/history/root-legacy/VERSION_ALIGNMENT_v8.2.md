# Arenyxa v8.2 version alignment (2026-09-11)

Official identity after this pass:

| Field | Value |
|---|---|
| `__version__` | `8.2` |
| `__package_version__` / pyproject `version` / `__display_version__` / `__distribution_version__` | `8.2.0` |
| `__engineering_build__` | `v8.2.0` |
| Windows filevers/prodvers | `8.2.0.0` |
| Plugin/runtime compatibility | `6.8.0` (intentionally unchanged) |

Corrected stale live tokens that still said 8.1 / 8.1.0 / 8.1.1:

- `src/arenyxa/__init__.py`
- `legacy/win7/src/arenyxa/__init__.py` (full identity fields + phase)
- `pyproject.toml`
- `src/arenyxa.egg-info/PKG-INFO`
- `HANDOFF.md` product label
- HAR/export creator version and default Repeater/Replay/crawler User-Agent product tags
- architecture product compatibility_level `8.1` → `8.2`
- leftover tests still asserting `filevers=(8,1,1,0)`

Historical reports named `Arenyxa_v7.0_*`, `V6.*` checklists, and "baseline: Arenyxa_v8.1.1" provenance fields were left as history.

`scripts/verify_v82_release_identity.py`: PASS

## Offline repair seed (2026-09-11 follow-up)

Regenerated with `python scripts/build_source_repair_seed.py` and `--win7`.

| Lane | Path | SHA-256 | Size |
|---|---|---|---|
| modern | `src/arenyxa/resources/repair_seed.zip` | `7aad1f4a2591fea3d1e5c55f7c281043fe36c613fc7b1fb15460d254abf95231` | 2690198 |
| win7 | `legacy/win7/src/arenyxa/resources/repair_seed.zip` | `dd14b6c8731e3d5b0d0a0bc20e161089c9d10eca86ad421960f966b639bfc498` | 1136561 |

`repair_manifest.json` `seed_sha256` matches the zip bytes. Previous tree had the manifest but **no zip**, which is exactly `REPAIR_SEED_INVALID` / fingerprint `NXF-C2CDCD687E1D`.
