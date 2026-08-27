# ADR: Plugin Boundary

Status: Accepted — Phase 1 Architecture Freeze

## Context

Arenyxa 6.8 accumulated a mature Web/Workflow/Dataset/Recovery runtime. Phase 1 freezes ownership before further platform expansion.

## Decision

PluginManager owns discovery/manifest compatibility; PluginSandbox/worker own isolated invocation.

## Consequence / invariant

Plugin failure or undeclared capability cannot become host-process authority.

## Compatibility

This ADR describes and constrains the existing runtime; it does not authorize a Phase-1 runtime rewrite or public API break.
