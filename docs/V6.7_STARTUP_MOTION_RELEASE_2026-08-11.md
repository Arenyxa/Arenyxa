# Arenyxa v6.7 — Startup Motion Release

## Release identity

- Public runtime: `6.7`
- Python distribution: `6.7.0`
- Plugin minimum-app comparator: `6.7.0`
- Modern installer: `Arenyxa_V6.7_Setup_x64.exe`
- Windows 7 Legacy installer: `Arenyxa_V6.7_Legacy_Win7_x64_Setup.exe`

## Startup transition

The v6.7 startup experience borrows the minimal interaction rhythm of X-style launch screens without copying its branding: one centered Arenyxa app icon appears on a quiet dark surface, real application initialization proceeds immediately behind it, and once the main workspace is ready the icon performs a restrained non-linear expansion while the splash fades away.

The animation is intentionally subordinate to readiness and recovery:

- no `sleep()` or cosmetic hold;
- no nested Qt event loop;
- second-instance activation does not flash a splash;
- DataRootLease failures do not flash a splash;
- bootstrap failures remove the splash before Recovery Mode appears;
- `MainWindow` is visible before animated exit begins;
- Reduce Motion removes animated exit;
- safe mode, smoke test and reduced-visual Legacy lanes bypass the splash;
- splash failures fall back to normal startup instead of becoming fatal dependencies.

## Stability hardening completed with v6.7

The startup audit also closed a pre-existing lifecycle gap. If `MainWindow` construction fails after bootstrap has already opened runtime services, Arenyxa now shuts down the `ApplicationContext` and releases the data-root process lease before returning the failure. This prevents a failed Presentation initialization from leaving a partially running backend until process exit.

## Validation gates

The release gate includes version/packaging consistency, Python 3.8 grammar compatibility, the full regression suite, Repair Seed integrity, Source Manifest integrity, the isolated `test-all` validation suite, bounded `stress-test extreme`, installer/static contracts, and clean re-extraction validation of the final source archive.
