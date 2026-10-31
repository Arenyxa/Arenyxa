# Arenyxa v8.0 beta17 Test Report

## Passed

- `compileall` for `src/arenyxa`: PASS.
- beta17 standard-library architecture suite: 7/7 PASS.
- existing navigation settings round-trip/validation regression functions: 3/3 PASS.
- existing navigation capability architecture regression functions: 6/6 PASS after adapting Enterprise-mode expectations; no test was deleted.
- focused PySide6 imports for Welcome Center, startup shell, theme transition, and MainWindow: PASS.
- `scripts/verify_beta17_release_identity.py`: PASS.
- source manifest regeneration: PASS; 1,109 files recorded.
- PEP 517 wheel build: PASS; `arenyxa-8.0.17-py3-none-any.whl`, SHA-256 `27e7678efa0e44b439710a594855701a3bf57756b52d4490f5ffd598718441c9`.

## Environment-limited checks

- Full `pytest` was requested but the supplied beta13 `.venv` points to a removed Python 3.11 executable and contains no pytest package. The available bundled Python 3.12 also has no pytest. Installation attempts did not produce a usable pytest install, so no full-suite PASS is claimed.
- The isolated `--smoke-test` reached real bootstrap and then failed in the pre-existing DPAPI key creation path with `CryptProtectData failed` under the managed sandbox identity, before MainWindow construction. MainWindow and the changed UI modules import successfully with compatible dependencies preloaded. A physical Windows user-session smoke run remains required.

## New coverage

Tests cover all five canonical modes, the eight-entry primary navigation invariant, Enterprise Console entry without identity, Developer Center entry without authority minting, event publication, settings persistence/restart restore, Personal scenario landing, and Root challenge fallback/activation.
