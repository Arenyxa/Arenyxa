# ADR: Capture Boundary

Status: Accepted — Phase 1 Architecture Freeze

## Context

Arenyxa 6.8 accumulated a mature Web/Workflow/Dataset/Recovery runtime. Phase 1 freezes ownership before further platform expansion.

## Decision

CaptureController owns adapter lifecycle, event buffering, session state and drop accounting.

## Consequence / invariant

Backpressure may cause explicit bounded drops; it may not silently fabricate completeness.

## Compatibility

This ADR describes and constrains the existing runtime; it does not authorize a Phase-1 runtime rewrite or public API break.
