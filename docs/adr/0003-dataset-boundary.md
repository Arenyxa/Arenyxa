# ADR: Dataset Boundary

Status: Accepted — Phase 1 Architecture Freeze

## Context

Arenyxa 6.8 accumulated a mature Web/Workflow/Dataset/Recovery runtime. Phase 1 freezes ownership before further platform expansion.

## Decision

DatasetVersionService and DataLineageService own revision identity, ancestry and lineage evidence.

## Consequence / invariant

A revision is complete and attributable or is not exposed as ready.

## Compatibility

This ADR describes and constrains the existing runtime; it does not authorize a Phase-1 runtime rewrite or public API break.
