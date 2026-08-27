# Arenyxa v8.0 beta17 UX Improvement Report

## Mode selection

The Welcome Center keeps the v7.3 card-based selection pattern. It adds Enterprise as a real mode and retains the existing Enterprise/Fleet sections. Mode selection is synchronous from the user's perspective and lands directly in the chosen workspace.

## First-run Personal setup

Five scenarios are available: website analysis, API debugging, network diagnostics, data collection, and network security learning. The choice is persisted and changes the Personal landing page without changing authority.

## Developer and Enterprise consoles

Developer Center now exposes real routes for Terminal, Runtime, Plugin SDK, Diagnostics, Authority, and Test Lab. Enterprise Console exposes Identity, Fleet, Server, Worker, Jobs, Audit, and Policy routes while retaining the full beta13 management UI.

## Startup and theme

The single-shell startup page now has determinate, smoothly advanced bootstrap stages at 10/30/50/70/85/100 percent and enforces a one-second minimum visible duration through a nested Qt event loop rather than sleeping the UI thread. Theme changes are coalesced and dispatched on the next event-loop turn through the existing crossfade renderer.

## Recovery

The existing Arenyxa Recovery Center, branded bootstrap recovery window, runtime health, logs, automatic repair, and diagnostic export paths were retained. Native Runtime/permission exceptions are still rendered through Arenyxa/Qt surfaces.
