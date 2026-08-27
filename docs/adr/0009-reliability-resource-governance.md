# ADR 0009 — Reliability and Resource Governance remain Core Runtime services

**Status:** Accepted for Phase 3  
**Date:** 2026-08-12

## Decision

Failure taxonomy, Resource Governor, Preflight Estimator and Performance Intelligence live in the application/runtime layer and remain independent of Qt, Enterprise identity and distributed transport.

The Governor produces ceilings; it never owns user hard limits and never raises them. Runtime components consume these ceilings through existing admission boundaries. Browser-based features share a bounded lease pool instead of inventing independent instance counters.

## Consequences

- Desktop and future Server/Worker can reuse the same policy semantics.
- Resource telemetry does not become authorization or durable business state.
- UI may display/modify configuration but cannot bypass runtime admission gates.
- Unknown failure classes remain fail-closed rather than silently retried.
