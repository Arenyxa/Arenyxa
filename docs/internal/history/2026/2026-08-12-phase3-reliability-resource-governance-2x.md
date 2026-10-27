# Arenyxa Phase 3 — Reliability / Resource Governance 2.x

Date: 2026-08-12  
Baseline: Arenyxa v6.8 Phase 1-2 source  
Scope: Phase 3 only

## 1. Objective

Phase 3 turns long-running stability into an explicit platform capability: a Run must stay bounded, resource pressure must reduce admission rather than amplify it, failures must have deterministic disposition, and recovery/test evidence must explain what happened. This phase deliberately does not introduce multi-machine workers, Enterprise IAM, Developer Authority, or a second Runtime.

## 2. Recovery taxonomy

`arenyxa.application.reliability.RecoveryTaxonomy` defines six fail-closed categories shared with `RuntimeRecoveryService`:

| Category | Default disposition | Automatic retry |
|---|---|---|
| Transient | bounded backoff/retry | only if idempotent and inside retry budget |
| Recoverable | stop at defined recovery boundary | no implicit replay |
| Configuration | reject before side effects | no |
| Permission | backend reject | no |
| Corruption | stop mutation, preserve evidence | no |
| Fatal | finalize and terminate with diagnostics | no |

Unknown exceptions are `Fatal`; the classifier never turns ambiguity into an automatic retry. `RuntimeRecoveryService.diagnose_failure()` exposes the same taxonomy at the Recovery Engine boundary.

## 3. Resource Governor

The new `ResourceGovernor` consumes bounded local telemetry and emits ceilings for requests, active Run workers, and browser instances.

Hard invariants:

1. User/request configuration remains the absolute ceiling.
2. Adaptive concurrency and the Governor can only move downward from that ceiling.
3. CPU/RAM/disk/browser pressure causes immediate bounded backoff.
4. Recovery is slower than backoff and requires consecutive healthy observations (hysteresis).
5. Critical disk pressure prevents new Runs and stops further result-producing admissions rather than risking a half-written storage state.
6. Browser resources are controlled by a shared lease pool used by Recorder and Browser Capture.
7. Metrics failure is advisory and logged; it never becomes a new hidden runtime failure.

The `RunOrchestrator` applies request ceilings live and refuses additional Runs when the Governor worker ceiling or critical disk gate is reached.

## 4. Preflight Estimator

`PreflightEstimator` produces ranges rather than false precision. Inputs include target count, expected average response size, request concurrency, latency, browser ratio and records-per-target. Outputs include:

- download bytes;
- low/high disk estimate;
- peak RAM estimate;
- low/high elapsed-time range;
- browser target count;
- `low` / `medium` / `high` risk with explicit risk markers.

The Tasks UI performs this estimate before submission. A high-risk non-preview Run requires explicit confirmation and includes current free disk / available-memory evidence when the local resource probe is available.

## 5. Performance Intelligence

`PerformanceIntelligence` consumes only bounded telemetry. URLs, payloads, cookies, headers and secrets are not retained. It can attribute reduced throughput to:

- HTTP 429 / rate limiting;
- origin latency;
- CPU pressure;
- memory pressure;
- disk pressure;
- retry amplification;
- local parse/extract cost;
- request-worker saturation;
- browser saturation;
- failure pressure.

The Developer Console `status` payload exposes the current Governor snapshot, performance explanation and plugin health for local diagnosis.

## 6. Workflow Test Lab

`WorkflowTestLab` adds deterministic workflow QA without mutating Dataset/Workflow durable execution state:

- structural dry-run;
- bounded fixtures;
- explicit mock HTTP;
- refusal to use real HTTP from a test fixture;
- canonical Golden Output SHA-256;
- reproducible regression suites;
- unexpected node errors fail a fixture by default.

Mocks are installed on a fresh in-memory test engine and therefore cannot leak into the production Workflow Engine.

## 7. Plugin reliability

The existing plugin process isolation is extended with:

- explicit input/output/memory/process/time budgets;
- Windows Job active-process limit in addition to memory and kill-on-close behavior;
- bounded per-plugin health history;
- consecutive-failure circuit breaker and temporary quarantine;
- health state surfaced to the Plugins page and Developer Console.

A quarantined plugin is rejected before spawning another child process.

## 8. Settings / Personalization separation

The prior combined Settings/Personalization page is split. `PersonalizationPage` exclusively owns theme cards, glass/material controls, motion, high contrast and UI scale. `SettingsPage` opens directly to operational configuration: performance, Resource Governor, concurrency, language, diagnostics, Repair Center and Developer Mode. This prevents visual presets from obscuring enterprise/operational controls.

## 9. Startup visual freeze

The approved startup visual implementation remains byte-identical to Phase 0:

- `startup_splash.py`: `a95bf948c3ddb2a165100711c59843e1eef013e7f9fb7e392ffbc38c9ddd5267`
- `startup_motion_math.py`: `81ce778eed5682ca042cdd1c7875ac46b20ea622d75c50d144d3b8043963231e`

Phase 3 does not redesign or retime startup animation.

## 10. Phase 3 No-Go boundaries

This phase does not implement:

- multi-machine Worker cluster;
- Enterprise account/Vault/Coordinator;
- Developer Authority or Official Developer Access;
- cloud-required resource management;
- stress-test escalation as a performance target.

A higher stress number is not a success criterion. Bounded behavior, no state drift, explicit recovery, reproducible workflow QA, and resource ceilings are.
