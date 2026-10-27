# Arenyxa V6.0 Low-End Device Performance Review

Date: 2026-08-09

## Goal

Reduce startup stalls, UI event-loop pressure, memory retention, and integrated-GPU rendering cost without removing Arenyxa capabilities. Efficiency mode changes budgets and presentation fidelity only; capture, search, workflows, plugins, diagnostics, and local data remain available.

## Runtime capability policy

Arenyxa now detects logical CPU count and total physical memory without adding a third-party dependency. New installations default to `performance_mode=auto`.

- Efficiency: constrained devices (normally <=4 logical CPUs or <=8.5 GiB RAM).
- Balanced: mid-range devices (normally <=8 logical CPUs or <=16.5 GiB RAM).
- High: larger devices.
- Explicit `quality` remains an override; explicit `efficiency` always uses the smallest budgets.
- Legacy `balanced` settings are allowed to downshift to Efficiency on genuinely constrained hardware so upgraded low-end installations benefit automatically.

## Major changes

### Lazy page construction

The main window no longer creates every page during startup. Pages are instantiated on first navigation. This removes startup construction of Network, Advanced Platform, Plugins, About, Settings/theme previews, and other unused surfaces.

### Qt/background budgets

The global Qt thread pool is bounded by the resolved policy and idle worker threads expire. Runner concurrency, capture queue capacity, capture flush size, result page size, log tail size, and retained network history are policy driven.

### Motion and compositor pressure

Efficiency caps semantic animation/frame sampling at 30 Hz; Balanced caps it at 60 Hz. High can follow high-refresh displays. Efficiency avoids QGraphicsOpacityEffect page reveals, staggered list reveals, continuous live-data interpolation, button opacity effects, and expensive glass specular rendering. Layout-critical width transitions remain available.

Frame sampling is suspended while the application is inactive to avoid background wakeups.

### Liquid Glass fallback

Efficiency preserves panel material hierarchy but uses a low-cost solid tint + simple rim path. It disables pointer specular and skips gradient-heavy rim/highlight composition. This avoids turning visual polish into frame drops on integrated GPUs or remote sessions.

### Network page

- Status and live-flush timers run only while the page is active.
- Capture writer batches are coalesced before Qt model mutation.
- Hidden Network pages do not retain a second in-memory copy of incoming packets; SQLite remains authoritative.
- Re-entering the page resynchronizes the selected session from SQLite.
- Retained rows and historical-load limits scale by performance mode.
- Waterfall visual density scales from 15/24/30 visible rows.

### Runner/UI progress

Runner progress callbacks are coalesced before crossing the queued Qt signal boundary. Fast tasks with many small requests no longer flood the GUI event queue with redundant status refreshes.

### Data and logs

Paged result fetch size and visible log block count scale down on constrained devices. This reduces JSON conversion, widget/model allocation, and text-document memory usage while retaining access to the complete persisted dataset via paging.

## Budgets

| Budget | Efficiency | Balanced | High |
|---|---:|---:|---:|
| Runner workers | <=2 | <=4 | configured value |
| Qt background workers | 2 | 4 | <=8 |
| Capture queue | 8,000 | 24,000 | 50,000 |
| Capture flush batch | 900 | 700 | 500 |
| Result page | 120 | 220 | 300 |
| Network retained rows | 5,000 | 10,000 | 20,000 |
| Network UI flush | 500 ms | 300 ms | 160 ms |
| Global status | 1,500 ms | 900 ms | 500 ms |
| Motion/frame cap | 30 Hz | 60 Hz | <=240 Hz |

These budgets are deliberately conservative and can be refined after Windows profiling on representative low-end systems.

## Validation

Pure-Python policy tests cover automatic mode resolution and budget bounds. Existing capture, HTTP resilience, scheduler, database, provenance, project-format, runtime-security, network-advanced, and server tests are rerun after the optimization. GUI smoke tests remain dependent on a PySide6-capable Windows/Qt environment.
