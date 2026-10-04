# Arenyxa v0.1 Release Status

## Release Identity

- Public: `v0.1`
- Package: `0.1.0`
- Windows: `0.1.0.0`
- Internal engineering baseline: `v8.2.0`
- Compatibility: `6.8.0`
- Distribution posture: community unsigned

## Publication Decision

**READY FOR SOURCE PUBLICATION.**

This decision covers committing and publishing the reviewed v0.1 source tree. It does not claim Authenticode signing or independent clean-machine qualification of the Windows installer.

## Validation Summary

- Full regression `full_08`: 1,869 passed, 3 skipped, 1 failed, 1 deselected. The sole failure was the stale approved application-icon hash.
- On 2026-10-04 the release owner explicitly approved the current `src/arenyxa/resources/icons/arenyxa.png` as the v0.1 application icon.
- Approved icon SHA-256: `EAF8A3F0D8B0AFEA1411F73C495764ECCF5167C69A72F01323ADAB60CBCC51F5`.
- After the approval record was updated, the targeted icon approval gate passed: 1 passed.
- Required PostgreSQL coverage recorded 7 required live cases passing with no gate issues.
- Bounded local P99 validation recorded 100.787 ms at 32 workers / 32 concurrency and 185.558 ms at 64 workers / 128 concurrency.
- Representative packaged-GUI flows passed during automated acceptance, including PCAP/PCAPNG handling and two Repair Center restart cycles.
- The release owner separately reports completion of manual GUI acceptance. This is recorded as owner validation, not as Codex automation evidence.

## Explicitly Deferred / Non-Blocking

- The 24-hour callback soak was explicitly reclassified by the release owner as deferred and non-blocking for v0.1. It is not reported as passed.
- Independent clean-Windows install, upgrade, rollback and uninstall qualification is not claimed by this source publication.
- Full multilingual and every-protocol GUI matrix coverage is not claimed.

## Publication Cleanup

Historical Beta/v6/v7/v8 engineering reports that were not required by active source, tests or release tooling were moved out of the repository root into `docs/internal/history/root-legacy/`. Their bytes and SHA-256 values are preserved in the archive manifest and indexed by `docs/internal/REPORT_INDEX.md`.

Files still required by active verification tooling remain at their established paths.

## Final Verdict

**READY FOR SOURCE PUBLICATION**

This verdict is deliberately narrower than “all Windows deployment scenarios qualified.” Binary/installer qualification claims must continue to reflect the tests actually performed.

## Evidence

- [Release history](RELEASE_HISTORY.md)
- [Testing](TESTING.md)
- [Installation](INSTALLATION.md)
- [Security](SECURITY.md)
- [Historical report index](internal/REPORT_INDEX.md)
