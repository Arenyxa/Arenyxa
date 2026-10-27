# Arenyxa v6.8 — Phase 0 Implementation & Stability Audit

Date: 2026-08-12  
Scope: Roadmap **Phase 0 only**

## Executive result

The source has been converted into a stricter **Phase 0 freeze candidate** without adding later-phase product functionality. Production/runtime source behavior was intentionally left unchanged. The only existing test-file change removes an unnecessary collection-time Qt dependency so non-Qt checks remain runnable in headless environments.

The automatable integrity/regression portion passed in the available Linux/Python 3.13 environment. The Roadmap-native Windows UX gate remains pending by design, so this audit does **not** authorize Phase 1 until the Windows verification record is completed.

## Changes reviewed

New:

- `scripts/verify_phase0_baseline.py`
- `scripts/phase0_gate.py`
- `docs/PHASE0_FROZEN_BASELINE_2026-08-12.md`
- `docs/PHASE0_KNOWN_LIMITATIONS_2026-08-12.md`
- `docs/PHASE0_WINDOWS_VERIFICATION_RECORD_2026-08-12.md`
- `docs/ROADMAP_BINDING_CONSTRAINTS_2026-08-12.md`
- this audit

Existing-file changes:

- `tests/test_v68_windows_dpi_accessibility_compat.py`: Qt-dependent imports moved into Qt-dependent tests; the subprocess DPR test now skips explicitly when neither PySide6 nor PySide2 is installed.
- `src/arenyxa/resources/repair_seed.zip` and `repair_manifest.json`: regenerated as one integrity pair.
- `SOURCE_MANIFEST.sha256`: regenerated after the final source/document changes.

No production `src/arenyxa/*.py` runtime behavior was modified in Phase 0.

## Validation performed in this environment

### Regression

The complete test-file set was executed in three deterministic regression groups to avoid treating external execution-environment time limits as a product failure:

- Group 1: **159 passed / 1 skipped / 0 failed**
- Group 2: **172 passed / 4 skipped / 0 failed**
- Group 3: **128 passed / 7 skipped / 0 failed**
- Aggregate: **459 passed / 12 skipped / 0 failed**

Skips are environment-specific: unavailable Qt binding for native/UI tests and Windows-only process-probe contracts. The upstream v6.8 freeze documentation already records a prior native/release regression; this Phase 0 audit treats that as inherited evidence, not as a substitute for the new native sign-off record.

### Syntax / compatibility

- Python compileall: PASS
- Existing Python 3.8 grammar gate: PASS, **92 source files**
- The two new Phase 0 scripts plus the modified test were separately parsed with Python 3.8 grammar: PASS

### Integrity

`verify_phase0_baseline.py` passed after cleanup and verifies:

- exact source inventory, including rejection of files omitted from `SOURCE_MANIFEST.sha256`;
- every source-manifest hash;
- Repair Seed ZIP CRC;
- Repair Seed outer SHA-256 and byte size;
- equality between external and embedded repair manifests;
- every embedded recovery payload hash against both ZIP contents and current source;
- v6.8 runtime/package/plugin compatibility identity;
- absence of build/cache/Git artefacts in the frozen delivery tree.

A negative probe was also executed by adding an untracked file. The verifier correctly failed with `Source manifest is not an exact inventory`, then returned to PASS after the probe was removed and the tree cleaned.

## Tooling limitation recorded, not hidden

Ruff was not available in the execution environment and package download was unavailable due network/DNS isolation. Therefore a **new independent Ruff run is not claimed** in this audit. The supplied v6.8 source includes prior release records stating that the critical Ruff gate passed. On the final native Windows verification host, `python scripts/phase0_gate.py` should be run with the declared development dependencies installed so Ruff is independently repeated.

## Native Windows hard gate

Still required before Phase 1:

- multi-monitor startup placement/continuity;
- per-monitor DPI and UI scaling;
- final X-style startup motion/handoff;
- Repair Center lifecycle;
- Browser/native Capture terminal lifecycle;
- `test-all`;
- bounded `stress-test standard` and `stress-test extreme`;
- representative persistence-failure path;
- clean extraction + Phase 0 verifier from the final ZIP.

See `PHASE0_WINDOWS_VERIFICATION_RECORD_2026-08-12.md`.

## Go / No-Go

**Automated engineering gate: PASS (with Ruff inherited, not independently rerun).**  
**Native Windows gate: PENDING.**  
**Roadmap decision: NO-GO to Phase 1 until native Windows sign-off is complete.**

This is intentionally conservative and follows the Roadmap definition that “code starts” or “new tests pass” is insufficient without integrity, fresh extraction, native Windows verification, and rollback evidence.
