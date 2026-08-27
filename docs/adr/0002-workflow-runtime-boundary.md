# ADR: Workflow Runtime Boundary

Status: Accepted — Phase 1 Architecture Freeze

## Context

Arenyxa 6.8 accumulated a mature Web/Workflow/Dataset/Recovery runtime. Phase 1 freezes ownership before further platform expansion.

## Decision

WorkflowEngine owns deterministic node semantics; WorkflowDatasetService owns checkpoint/revision integration and resume consistency.

## Consequence / invariant

A resumed execution must not duplicate committed output or non-idempotent effects.

## Compatibility

This ADR describes and constrains the existing runtime; it does not authorize a Phase-1 runtime rewrite or public API break.
