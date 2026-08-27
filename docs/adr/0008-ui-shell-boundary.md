# ADR: UI Shell Boundary

Status: Accepted — Phase 1 Architecture Freeze

## Context

Arenyxa 6.8 accumulated a mature Web/Workflow/Dataset/Recovery runtime. Phase 1 freezes ownership before further platform expansion.

## Decision

Presentation consumes ApplicationContext services and emits user intent. It is not an authorization or persistence layer.

## Consequence / invariant

Hidden/disabled controls are presentation only; backend enforcement and durable truth remain outside UI.

## Compatibility

This ADR describes and constrains the existing runtime; it does not authorize a Phase-1 runtime rewrite or public API break.
