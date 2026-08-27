# ADR: Recovery Boundary

Status: Accepted — Phase 1 Architecture Freeze

## Context

Arenyxa 6.8 accumulated a mature Web/Workflow/Dataset/Recovery runtime. Phase 1 freezes ownership before further platform expansion.

## Decision

RuntimeRecoveryService owns startup reconciliation of interrupted durable state.

## Consequence / invariant

Only defined invariants are repaired; ambiguity/corruption fails closed with diagnostics.

## Compatibility

This ADR describes and constrains the existing runtime; it does not authorize a Phase-1 runtime rewrite or public API break.
