# ADR: Run Runtime Boundary

Status: Accepted — Phase 1 Architecture Freeze

## Context

Arenyxa 6.8 accumulated a mature Web/Workflow/Dataset/Recovery runtime. Phase 1 freezes ownership before further platform expansion.

## Decision

RunOrchestrator owns Run lifecycle, cancellation, progress and durable run-state transitions. HTTP/storage are adapters; UI cannot mutate Run truth directly.

## Consequence / invariant

Retries are bounded and idempotency-aware; failure cannot leave UI state ahead of durable state.

## Compatibility

This ADR describes and constrains the existing runtime; it does not authorize a Phase-1 runtime rewrite or public API break.
