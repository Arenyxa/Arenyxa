# Arenyxa v7.0 Stable Release — 2026-08-14

## Release identity

Arenyxa v7.0 promotes the cumulative Phase 1–12 hardened development line to the **7.0 product release identity**. The public runtime version is `7.0`, the Python distribution version is `7.0.0`, and Windows file metadata is `7.0.0.0`. The modern installer is `Arenyxa_V7.0_Setup_x64.exe`; the isolated Windows 7 Legacy Enterprise installer is `Arenyxa_V7.0_Legacy_Win7_x64_Setup.exe`.

This promotion deliberately **does not** pretend that the plugin/runtime compatibility contract changed. `__compat_version__` remains `6.8.0` until an explicit compatibility migration is designed, reviewed, and tested. The historical `arenyxa` Python/CLI namespace also remains supported so existing integrations are not broken by the product version promotion.

## Included platform scope

The v7.0 source integrates the Phase 1–12 architecture/contracts, Web Intelligence, Reliability/Resource Governance, Security Foundation, Official Developer Trust, Local Enterprise Identity/RBAC, Enrollment/Device Trust, Office Coordinator, Enterprise Governance, Enterprise Server/Worker distributed runtime, and Release Hardening/LTS foundations in one Core Runtime line.

The startup visual baseline is intentionally frozen. The v7.0 version promotion does not alter the approved splash/handoff implementation or its motion math.

## Release hardening

The build chain now has an explicit v7.0 release-identity gate. It verifies the runtime/package versions, Windows file metadata, modern and legacy Inno Setup names, release-attestation version, launcher identity, and the distinction between product release version (`7.0.0`) and runtime/plugin compatibility identity (`6.8.0`). The release gate is executed by the packaging scripts before building binaries.

Worker health reporting publishes the real product package version while distributed registration continues to negotiate the explicit compatibility identity. This prevents a future product-version bump from silently becoming a protocol/plugin compatibility change.

## Automated verification

The final release tree and a fresh extraction were exercised through the release-identity, compile/grammar, static-security, startup-freeze, independent Welcome window, UI button-wiring, Phase 1-12 targeted, integrity, and historical regression gates. The complete historical pytest regression on the fresh extraction is **592 passed / 12 environment skips / 0 failed**. The skips are limited to Qt/Windows-native probes unavailable on the headless validation host; no failing test was reclassified as a skip.

The frozen startup files remain byte-identical to the approved baseline: `startup_splash.py` SHA-256 `a95bf948c3ddb2a165100711c59843e1eef013e7f9fb7e392ffbc38c9ddd5267` and `startup_motion_math.py` SHA-256 `81ce778eed5682ca042cdd1c7875ac46b20ea622d75c50d144d3b8043963231e`.

## Stable/GA boundary

The source is branded and packaged as the v7.0 Stable release line, but the Phase-12 policy remains fail-closed: automated regression is not a substitute for real Windows validation, a distributed-failure drill, migration/rollback evidence, independent security review, and official release signing. `ReleaseGateReport` continues to reject Stable/Enterprise promotion when those operator/native gates are missing.

Arenyxa release signing is a separate trust domain. Developer Root, Owner Authority keys, Enterprise Root keys, and private Authority state must never be reused as release-signing keys or included in the installer.
