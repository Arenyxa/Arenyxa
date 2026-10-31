# Arenyxa v6.8 Stable Performance + Startup Continuity Hotfix

Date: 2026-08-11

## Scope

This source hotfix continues the v6.8 Stable line without changing the public, package, installer,
or plugin/API compatibility version. It preserves Repair single-console relaunch, Capture terminal
progress cleanup, UI scaling, adaptive request admission, and the Stable pause/resume transaction
guards. Git history and Inno Setup output are intentionally outside this delivery.

## Performance regression diagnosis

The reported Stable result at four workers was about `320 ops/s` with `P95 54 ms`, versus the
earlier beta observation of `529.8 ops/s` with `P95 19.95 ms`.

The release trees showed that this was not a Stable hot-path code regression:

- beta and pre-hotfix Stable `developer_validation.py` were byte-identical
  (`FCCFA4A5B19488CFAEF77E683B14E69C387F01710DB274EE72BB2207AA49F85C`);
- beta and Stable SQLite storage were byte-identical;
- beta and Stable atomic-file I/O were byte-identical;
- the Stable Runner differences were pause/resume token exception guards, which are not used by
  the isolated mixed-workload stress level.

The actual distortion was inside the diagnostic: `tracemalloc` wrapped the complete timed
multi-threaded ramp. Python allocation tracing serializes allocation bookkeeping across all worker
threads and therefore manufactured additional lock contention at the exact concurrency levels being
measured. A same-runtime A/B probe restored the four-worker result to roughly `465-466 ops/s` when
that instrumentation was removed from the timer.

## Performance fix

- The memory-safety signal remains, but runs as a bounded representative pre-timing probe.
- SQLite/FTS and atomic-file paths are warmed before the level clock starts.
- The timed section contains exactly the requested operation count.
- The compatibility output key `peak_python_memory_mib` remains available.
- `memory_probe_peak_mib` explicitly communicates the revised measurement boundary.
- Integrity checks, error accounting, stable/unstable detection, time ceilings, and the adaptive
  worker recommendation algorithm are unchanged.

Three consecutive post-fix Standard runs in the same Python 3.11.9 / lxml 6.1.1 environment gave:

| Run | 4-worker throughput | 4-worker P95 | Errors | Recommended |
|---:|---:|---:|---:|---:|
| 1 | 511.73 ops/s | 33.42 ms | 0 | 4 |
| 2 | 465.12 ops/s | 34.88 ms | 0 | 4 |
| 3 | 511.73 ops/s | 30.45 ms | 0 | 4 |

The average was `496.19 ops/s / P95 32.92 ms`: about 55% more throughput and 39% lower P95 than
the reported Stable regression run. Throughput is within about 6.4% of the earlier beta observation.
Disk scheduling and Windows security/indexing activity can still move the SQLite-heavy P95, so the
result remains a bounded local diagnostic rather than a universal hardware score.

The post-fix Extreme ramp completed all ten levels from 1 through 64 workers: 6,000 timed
operations, zero errors, no unstable level, and a four-worker recommendation. The 64-worker P95
reached `2473.36 ms`, accurately exposing the single-database writer queue under deliberate
over-subscription. The result is not treated as a reason to widen thresholds; it is evidence that
normal adaptive admission should remain near the measured four-worker sweet spot.

## X-inspired continuous startup handoff

The launch surface now uses one center-origin visual gesture:

1. the centered Arenyxa mark remains on the clean `#030706` surface;
2. the mark continuously enlarges to 1.92x with quintic soft endpoints;
3. the ready MainWindow client is captured once while it is still covered;
4. a circular aperture grows from the same center and reveals that exact client frame;
5. the overlay disappears only after the aperture covers the window diagonal.

This avoids per-frame pixmap allocation and avoids exposing the live workspace between two unrelated
window paints. The top-level bootstrap surface and child handoff surface use the same resolved launch
rectangle, center, and icon size. The mask radius is derived from the window diagonal, so portrait,
ultrawide, maximized, multi-monitor, and logical high-DPI geometries all finish fully uncovered.

Balanced/Quality/Efficiency use `520/600/360 ms` exits. Reduce Motion performs the same prepared
handoff without cosmetic scaling or animation. Safe mode, smoke test, and reduced-visual runtimes
continue to bypass the animated surface.

## Preserved regression contracts

- Repair relaunch still prefers `pythonw.exe`, detaches console handles, and keeps one visible
  progress terminal.
- Capture `completed`, `failed`, `cancelled`, and `idle` still clear global indeterminate progress.
- Automatic/manual UI scaling remains 85%-160% compatible.
- Adaptive request admission and its four-slot local floor remain intact.
- Pause/resume token and durable-state failure boundaries remain intact.
- Launch geometry remains shared across startup, MainWindow, Recovery Mode, and the target display.
- Stale French/Japanese hot-switch regression expectations now match the shipped native noun labels
  `Relecture de requête` / `リクエスト再生`; user-entered text preservation remains covered.

## Verification

The final source is required to pass Python compilation, Python 3.8 grammar, critical Ruff, native
Qt mask rendering, startup math/geometry/accessibility, performance-probe contracts, Standard and
Extreme stress ramps, Repair Seed integrity, Source Manifest integrity, complete pytest regression,
and clean-ZIP CRC/extraction verification before delivery.

Before integrity artifacts were regenerated, all non-integrity historical tests completed with
`445 passed / 1 skipped / 0 functional failures`; the only discovered mismatch was the stale
French/Japanese translation expectation described above, whose focused regression then passed.
