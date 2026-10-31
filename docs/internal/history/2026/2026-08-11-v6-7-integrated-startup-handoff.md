# Arenyxa v6.7 — Integrated Startup Handoff & Multi-Monitor Fix

Date: 2026-08-11

## Problem closed

The original v6.7 splash and MainWindow used two independent placement systems. The startup
surface selected `QApplication.primaryScreen()`, while MainWindow later restored `window.ini`
geometry. On dual-monitor systems this could make the brand mark appear on one display and the
workspace appear on another. The frameless splash also had its own dimensions, so even on one
screen the transition could feel like one program closing and a second program opening.

## New launch model

Arenyxa now resolves one `LaunchGeometryPlan` before the startup surface is created. The plan:

- restores the previous window rectangle through Qt;
- prefers the last persisted display name when that display is still connected;
- otherwise chooses the connected display containing most of the restored rectangle;
- falls back to the display under the pointer, then the primary display;
- clamps stale/off-screen geometry to the selected display's current available area;
- preserves the maximized preference;
- is shared verbatim by the startup surface and MainWindow.

MainWindow now persists both `screen_name` and `maximized` alongside its normal Qt geometry/state.
Its motion refresh-rate policy is also derived from the resolved target display instead of always
using the primary display.

## Integrated visual handoff

The initial top-level brand surface remains non-blocking while bootstrap runs. When MainWindow is
ready, Arenyxa creates an `ArenyxaStartupHandoffOverlay` as a child of MainWindow and paints it
before the temporary top-level splash is removed. The child overlay then performs the short
OutCubic brand reveal directly over the real workspace.

This means the visible startup frame, display, size, center point and final workspace are one
continuous visual identity. Reduce Motion keeps a static handoff frame without cosmetic motion.
The overlay is mouse-transparent and never controls application readiness.

If the in-window handoff cannot be created or animated, the still-visible top-level startup surface
uses its existing best-effort fallback exit. Recovery Mode is centered on the same resolved launch
display rather than being left to independent OS placement.
