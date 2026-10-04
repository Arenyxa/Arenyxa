# Arenyxa version identity

The current public identity is **v0.1**, package **0.1.0**, Windows PE **0.1.0.0**. This is the **public source release** and remains **community unsigned**. `RELEASE_IDENTITY.json` is the machine-readable identity record; source publication does not imply Authenticode or release-attestation signatures, nor independent clean-machine installer qualification.

| Identity | Value | Meaning |
| --- | --- | --- |
| Public display / `__version__` / `__display_version__` | `0.1` | Desktop, CLI and product label |
| Python package / distribution | `0.1.0` | PEP 440 package, product manifests and exports |
| Windows numeric file/product tuple | `0.1.0.0` / `(0,1,0,0)` | PE version metadata |
| Engineering baseline / internal version | `v8.2.0` / `8.2.0` | Retained implementation provenance |
| Engineering phase | `8` | Retained internal phase identifier |
| Runtime/plugin compatibility identity | `6.8.0` | Independent compatibility negotiation; not a product display label |
| Enterprise protocol | Current `2`, minimum `1` | Independent N/N-1 protocol contract |
| Schema and fixture revisions | Existing values | Each migration/settings/workflow/artifact schema keeps its own contract |

Modern and legacy package metadata share the public identity. The legacy runtime remains **NOT TESTED** for this candidate; it does not gain modern feature parity through this metadata update.

Run `python scripts/verify_release_identity.py` with the supported environment to verify current source metadata. Historical verifier command names remain compatibility aliases for this current gate. A PASS covers source identity consistency only. It does not certify a PE built previously, authorize release promotion or validate a runtime. Release-status fields may only change with reviewed evidence and a corresponding update to their verification contract.

Do not globally replace `8.x`, `6.8.0`, migration numbers or protocol versions. Historical `V8_2_RELEASE_IDENTITY.json`, V8.x/Beta documents, audit dates, compatibility fixture manifests and hashes remain evidence for the inputs they originally described. Tests named after historical engineering phases may assert the current product facade; their filename alone is not a reason to keep a stale current-product assertion.

Installer AppId, application data names and file associations are retained. Moving the numeric product version from engineering 8.x to public 0.1 is not a proven in-place upgrade strategy. An older-engineering-version installation, a clean install, migration rollback and uninstall/data retention must be tested explicitly on suitable disposable Windows environments.

Release signing, Authenticode, Developer identity and Enterprise Root authority are separate trust systems. This community candidate does not use Root/Owner/Enterprise credentials to sign the product. See [SECURITY.md](SECURITY.md) and [historical record](docs/RELEASE_HISTORY.md).
