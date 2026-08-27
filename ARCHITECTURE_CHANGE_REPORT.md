# Arenyxa v8.0 beta17 Architecture Change Report

## Scope

beta17 is an incremental change over `Arenyxa_v8.0_beta13`. No Runtime rewrite, SQLite schema migration, Supervisor replacement, or feature deletion was performed.

## Additive architecture

- Added a unified `ExperienceContext` containing `mode`, `identity`, `permissions`, `capabilities`, `workspace`, and the compatibility `NavigationContext` projection.
- Added `ExperienceContextController` as the single persistence/context/event boundary for mode changes.
- Added `ModeChangedEvent` and synchronous subscriber publication after settings persistence.
- Added `NavigationPolicyEngine` to rebuild visible navigation and order it using the active workspace policy.
- Added five canonical modes: Personal, Professional, Developer, Enterprise, and Root Developer. The beta13 `GUIDED` and `ADVANCED` enum names remain as aliases.
- Split theme switching into a coalescing `ThemeTransitionController`; the existing motion crossfade remains the renderer.

## Preserved systems

The existing bootstrap flow, Runtime Supervisor, External Supervisor lifecycle, SQLite stores, Security Kernel, Enterprise Identity/Enrollment/Coordinator/Governance/Server, Developer Access, Root Authority challenge, Page Registry, Recovery Center, and all registered pages remain present. Database schema code was not changed.

## Compatibility adapters

`experience_profile` remains the persisted UX key. `developer_mode` remains a compatibility/risk-acceptance gate for operational shell behavior; it is no longer used as the source of truth for Experience Mode. Existing beta13 page IDs and QWidget types are retained.
