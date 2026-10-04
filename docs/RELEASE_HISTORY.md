# Release and engineering history

## Public v0.1 — 2026-10-04

Arenyxa public source release identity is `v0.1` / package `0.1.0` / Windows PE `0.1.0.0`. The retained engineering baseline is `v8.2.0`, and runtime/plugin compatibility identity remains `6.8.0`. The distribution posture is **community unsigned**.

The v0.1 promotion preserves engineering provenance and keeps database, protocol, schema and plugin compatibility contracts independent from the public product version. See [version policy](../VERSIONING.md), [current release status](RELEASE_STATUS.md) and [current identity](../RELEASE_IDENTITY.json).

For this source-publication decision, the release owner explicitly approved the current application icon, reported completion of manual GUI acceptance, and reclassified the optional 24-hour callback soak as deferred/non-blocking. These decisions do not create claims for tests that were not performed; independent clean-machine installer qualification remains outside the source-publication claim.

## Preserved engineering records

Earlier filenames and version labels describe historical engineering snapshots. Their original assertions and results remain historical source material and do not redefine the public v0.1 identity.

- [v8.2 engineering identity](../V8_2_RELEASE_IDENTITY.json) retains the implementation provenance preceding the public identity change.
- [v7.0 engineering release record](V7.0_STABLE_RELEASE_2026-08-14.md) records the earlier integrated platform work.
- [v6.8 engineering record](V6.8_STABLE_RELEASE_2026-08-11.md) and [v6.7 startup-motion record](V6.7_STARTUP_MOTION_RELEASE_2026-08-11.md) retain their contemporary findings.
- [v6.6 engineering record](V6.6_STABLE_RELEASE_2026-08-10.md) and [Windows 7 compatibility design](V6.6.1_WINDOWS7_LEGACY_COMPATIBILITY_6X_REVIEW_2026-08-09.md) explain the frozen legacy lane.
- Root-level Beta/v6/v7/v8 reports that are not required by active tooling are archived under [internal historical reports](internal/REPORT_INDEX.md).

Migration fixtures retain their original migration identifiers and recorded digests. Public version promotion does not rewrite those historical bytes or certify the legacy runtime.
