# Arenyxa v6.8 — Roadmap Phase 0 Frozen Baseline

Date: 2026-08-12  
Roadmap stage: **Phase 0 — 冻结 v6.8 核心基线**  
Release identity: runtime `6.8`, package/plugin compatibility `6.8.0`

## Scope

This phase deliberately adds **no Enterprise Identity, Developer Login, Server Runtime, new product surface, or large namespace/folder refactor**. It converts the already hardened v6.8 source into a baseline whose integrity and recovery artifacts can be independently verified before later architecture work starts.

The phase preserves the historical `arenyxa` implementation namespace and the public `arenyxa` facade, existing CLI/plugin/API compatibility, the two Windows runtime lanes, and the current UI/runtime behavior.

## Phase 0 hardening added

1. `scripts/verify_phase0_baseline.py`
   - verifies `SOURCE_MANIFEST.sha256` as an **exact inventory**, not merely a list of hashes;
   - rejects files present in the source tree but missing from the manifest;
   - verifies Repair Seed ZIP CRC, outer SHA-256/size, embedded manifest, every embedded payload hash, and equality with current source files;
   - verifies v6.8 release identity and rejects cache/build/Git artefacts from the frozen source tree.
2. `scripts/phase0_gate.py`
   - provides one standard automated gate for compileall, Python 3.8 grammar, Ruff, full pytest regression, and Phase 0 integrity;
   - explicitly refuses to treat offscreen Qt as native Windows UX proof.
3. Headless regression collection robustness
   - `test_v68_windows_dpi_accessibility_compat.py` no longer imports Qt-dependent geometry classes at module import time;
   - non-Qt Windows compatibility tests can therefore still run when Qt is unavailable, while tests that actually need Qt continue to skip through the existing `qapp` fixture.
4. Phase 0 records
   - this freeze record;
   - `PHASE0_KNOWN_LIMITATIONS_2026-08-12.md`;
   - `PHASE0_WINDOWS_VERIFICATION_RECORD_2026-08-12.md`.

## Integrity ordering

The frozen artefacts must be generated in this order after the final source edit:

1. rebuild Repair Seed / Repair Manifest;
2. rebuild Source Manifest;
3. run automated Phase 0 gate;
4. create source ZIP;
5. validate ZIP CRC and clean extraction;
6. rerun the automated gate from the clean extraction;
7. record ZIP SHA-256 externally;
8. complete native Windows verification and sign off the Windows record.

This order avoids circular self-hashing and ensures the source manifest commits the final Repair Seed pair.

## Go / No-Go interpretation

Automated success is necessary but **not sufficient**. Native Windows multi-monitor/DPI/startup, Repair, Capture, `test-all`, and safe Standard/Extreme stress verification remain a hard manual/native gate. Until that record is completed on a real Windows host, the package is a **Phase 0 freeze candidate** rather than permission to enter Phase 1.

## Compatibility and rollback

No public runtime behavior is intentionally changed. The only test change removes an unnecessary collection-time Qt dependency. Rollback is module-local: remove the two Phase 0 scripts/docs and revert the test import relocation; production source remains unchanged.
