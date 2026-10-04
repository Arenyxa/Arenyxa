# Arenyxa v8.0 Official Source Release Notes

Arenyxa v8.0 is promoted from the final engineering candidate to the official stable source identity.

## Stable identity

- Display version: `8.0`
- Package version: `8.0.0`
- Windows file version: `8.0.0.0`
- Release channel: `stable`
- Artifact name: `Arenyxa_v8.0`
- Runtime/plugin compatibility identity: `6.8.0`

## Startup launcher finalization

- Source launch remains standardized on `python.exe -m arenyxa`; `pythonw.exe` is intentionally not preferred so diagnostics remain observable.
- The environment probe uses `System.Diagnostics.ProcessStartInfo` and separately captures stdout, stderr, process start state, Python version, working directory, and ExitCode.
- Probe execution now has a bounded timeout path that returns `ExitCode = -2` with preserved stdout/stderr instead of hanging the launcher indefinitely.

## Promotion policy

This promotion does not invalidate existing 6.8-compatible plugins, workers, or distributed metadata. Environment-dependent certifications such as native Windows driver capture, real PostgreSQL multi-node stress, TPM/CNG, DPAPI, SCM, and 24-hour soak tests must continue to report `NOT_EXECUTED` unless run on suitable hardware.

## Small finalization optimizations

- Current v8 artifact identity is stable-only across release metadata, runtime namespace, Windows packaging, manifests, and generated source archive names.
- v8 phase regression test filenames no longer carry pre-release identity; historical v6 pre-release compatibility tests are retained as compatibility history.
- Physical QA guidance is now separated from automated CI so official release evidence does not confuse logic correctness with hardware certification.
