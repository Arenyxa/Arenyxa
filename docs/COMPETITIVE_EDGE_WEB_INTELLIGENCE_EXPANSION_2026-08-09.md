# Arenyxa Competitive Edge / Web Intelligence Expansion

Date: 2026-08-09  
Scope: explainable collection strategy, cross-tool context bridge, portable workflows, compatibility regression, UI/taskbar integration.

## Goal

This iteration deliberately avoids a feature-count race. The objective is to make Arenyxa better at one end-to-end job: understand how a web experience exposes data, explain the tradeoffs, turn the selected path into a reviewable workflow, and keep the workflow testable as the site changes.

## 1. Explainable Web Intelligence Blueprint

`application/competitive.py::WebIntelligenceEngine` sits above SmartPath 2.0. It does not replace runtime evidence with opaque heuristics. It converts the existing response/capture evidence into:

- an auditable decision trace;
- per-engine relative estimates for completeness, stability and resource efficiency;
- heuristic latency/RAM/request estimates explicitly marked as estimates;
- a fallback chain rather than a single fragile choice;
- risk flags for rate limiting, authentication/session dependence, origin instability, low confidence and scale pressure;
- a starter Workflow that can be inspected in Workflow Debugger.

The recommendation preserves SmartPath unless the explainable scoring layer finds a materially stronger candidate, limiting unexpected strategy flips.

## 2. Zero-copy Context Bridge

`ContextBridgeService` converts captured Network events into RequestSpec, generated code and starter Workflows. Sensitive headers/cookies are omitted by default. The UI adds:

- `Top API → HTTP Builder` in SmartPath;
- `Request → Workflow` in HTTP Builder;
- `Blueprint Workflow → Debugger` in Explainable Blueprint.

This reduces the common workflow of manually copying a request between browser DevTools, an API client, source code and an automation editor.

## 3. Open Workflow Portability

`WorkflowPortabilityService` introduces `arenyxa.workflow/v1`, a deterministic JSON interchange envelope with:

- stable canonical serialization;
- SHA-256 integrity verification;
- explicit node/edge validation;
- bounded document/node sizes;
- inline-secret detection, requiring `${secret.name}` style references by default.

The format is intended to remain Git/diff/PR friendly rather than becoming an opaque binary project artifact.

## 4. Compatibility Lab

`CompatibilityLab` adds a deterministic offline regression harness. The built-in fixtures currently cover:

- direct JSON;
- Next.js + API discovery;
- static HTML;
- GraphQL;
- JavaScript-heavy browser fallback;
- session-dependent browser fallback.

The output reports engine accuracy, data-source recall, pass rate and tag-level results. The UI and report explicitly state that bundled fixtures are local deterministic regression evidence, not a claim about live third-party website compatibility.

The harness is designed so permissioned captured fixtures can be added in CI later, forming the basis for a real compatibility matrix.

## 5. Reliability Advisor

`ReliabilityAdvisor` converts drift signals into ordered recovery actions. It can combine data-quality regression, selector confidence, error rate, schema drift and rate-limit signals, recommending adaptive throttling, selector self-heal, schema diff, quality gates or SmartPath replanning.

## 6. UI / Windows shell changes

Intelligence Studio adds:

- Explainable Blueprint;
- Compatibility Lab;
- Workflow Portability.

The main toolbar adds `◆ Blueprint`. Command Palette and System Tray gain Blueprint / Compatibility entries. Shortcuts:

- `Ctrl+Shift+B`: Explainable Blueprint;
- `Ctrl+Shift+L`: Compatibility Lab.

`WorkspacePage.operationProgress` allows long advanced operations to publish bounded progress to the global shell. MainWindow displays this through the top progress component, Windows taskbar progress state and tray tooltip when there is no higher-priority active Run/Capture.

## 7. Security / privacy boundaries

- Context Bridge drops Authorization, Cookie, Proxy-Authorization, API-key/token style headers by default.
- Portable workflow export refuses likely inline secrets unless explicitly overridden by code.
- Compatibility fixtures are local/offline and do not probe third-party websites.
- Cost/performance values in Blueprint are labelled heuristic estimates; they are not benchmark claims.
- Existing Local-first, Developer Mode and Repair/Provenance boundaries remain unchanged.

## 8. Test coverage added

`tests/test_competitive_edge.py` covers:

- explainable decision trace and engine estimates;
- rate-limit/session risk reporting;
- sensitive-data-safe Context Bridge;
- deterministic portable Workflow round-trip and tamper detection;
- inline-secret rejection;
- deterministic Compatibility Lab baseline;
- Reliability Advisor action ordering.

