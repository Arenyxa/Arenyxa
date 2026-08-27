# Arenyxa V6.2.1 — Autopilot Learning Integration Audit

## Scope

This maintenance release integrates the independently developed V6.0 Autopilot Learning Foundation into the V6.2 Network Capture Enriched mainline by three-way merge against the shared V6.0 Reliability/Stability baseline. The merge intentionally preserves V6.1 Unified Network Core and V6.2 Body Store/capture enrichment rather than replacing those files with the older branch.

## Integrated components

- `application/autopilot.py`: bounded local `ExperienceStore`, feedback-aware `AutopilotEngine`, deterministic `FailureClassifier`, and `SelectorRecoveryRanker`.
- `NextGenFeatureHub`: constructs the local experience store under the Arenyxa data root and exposes the Autopilot service.
- Intelligence Studio: Autopilot analysis, explicit success/failure feedback, local statistics, and redacted JSONL export.
- Main window/shell: Autopilot quick action, command-palette entry, tray action, and keyboard shortcut.
- Regression coverage: original Autopilot learning tests are retained alongside V6.1/V6.2 Network Core tests.

## Merge invariants

1. No V6.1/V6.2 normalized network table or Body Store migration is removed.
2. `NetworkEvent` remains the compatibility input for Autopilot in this release; normalized Network Core remains authoritative for capture persistence.
3. Autopilot advice cannot execute a network strategy by itself; deterministic planner/runtime boundaries remain in force.
4. Experience data is stored separately from primary user datasets so experimental learning schema failures cannot block core database startup.
5. Generated repair/source-integrity artifacts are regenerated after merge; branch copies are never selected as conflict resolutions.

## Versioning

V6.3 remains reserved for Replay + API Map. This integration is therefore released as **6.2.1** rather than consuming the V6.3 milestone.
