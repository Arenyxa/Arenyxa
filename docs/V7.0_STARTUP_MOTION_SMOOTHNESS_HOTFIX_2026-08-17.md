# Arenyxa v7.0 Startup Motion Smoothness Hotfix — 2026-08-17

## Scope

This is an explicit revision of the previously frozen startup implementation. The approved visual
composition is preserved: same launch geometry, centered Arenyxa mark, scale/fade timing curve,
centered circular workspace reveal, and in-window handoff. The change targets frame pacing only.

## Changes

- Replaced the startup handoff's shared Qt animation-clock dependency with a refresh-aware precise
  frame driver.
- Reads the current display refresh rate and supports a bounded 30–240 Hz target.
- Uses `Qt.PreciseTimer` only as a wake-up mechanism; animation progress is derived from
  `time.perf_counter()` so delayed frames do not accumulate timing drift.
- Keeps the existing quintic smootherstep / handoff visual curve unchanged.
- Uses native-size workspace snapshot painting when capture geometry/DPR already matches the overlay,
  avoiding unnecessary full-window smooth resampling on each frame.
- Retains Reduce Motion, efficiency mode, launch-geometry sharing, and the overlay-first handoff.

## Approved baseline

- `src/arenyxa/presentation/startup_splash.py`: `5bcec53f10475a27c4b7addf3a048a63484c0e3cab6a952177a193195a3f32f7`
- `src/arenyxa/presentation/startup_motion_math.py`: `f19285a473524602e55b3bd33533774f8831d352fbecdac6e296137965ab91af`

Future startup changes should continue to require explicit approval and update the baseline only after
the startup/multi-monitor/DPI regression gates pass.
