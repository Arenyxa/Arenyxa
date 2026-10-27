# Arenyxa Phase 2 — Web Intelligence 2.x

Suggested roadmap milestone: Arenyxa 6.9. This source candidate intentionally retains the 6.8 package identity until the release gate so historical regression remains unchanged.

## Web Intelligence Center

`WebIntelligenceCenter` composes the existing explainable SmartPath engine, Data Source Discovery, Capture/Network events, GraphQL/WebSocket/SSE inspectors, Context Bridge, Selector Studio, Browser Recorder and Web Time Machine behind one application facade. Existing UI surfaces remain compatible; the SmartPath surface is now backed by the center rather than creating a second Web runtime.

## SmartPath 2.x execution path

Every plan now exposes an explicit three-stage path:

1. inspect direct/static HTML when available;
2. prefer structured endpoints when safe and sufficiently evidenced;
3. retain browser discovery/execution as a fallback for JavaScript, login or interaction requirements.

The selected engine still uses the established scoring logic; the execution path is explainability evidence, not a hidden override.

## Safe Capture → Workflow conversion

Captured endpoints are classified by method, response/data hints and sensitivity. Automatic Workflow conversion requires all of the following:

- structured API/XHR/Fetch/GraphQL evidence;
- idempotent method (`GET`, `HEAD`, `OPTIONS`);
- no sensitive query/header/cookie/sensitivity flag.

Sensitive parameter **values are never retained in a persistable candidate**. Non-idempotent requests remain review-only. The UI exposes `Top API → Workflow` only through this gate.

## Selector Recovery 2.x

Selector fingerprints now include bounded ancestor-structure evidence and a deterministic structure hash. Recovery candidates include match count, uniqueness risk, historical-success evidence, and an explicit auto-apply eligibility flag.

`heal_with_policy()` separates the default `review-only` mode from `auto-apply`. Auto-apply requires a unique, high-confidence candidate. Legacy `heal()` remains compatible.

## Recorder semantic compiler

Browser Recorder keeps the same portable action format, while `compile_semantics()` groups actions into semantic stages including login, search, pagination, extraction and download. `to_semantic_workflow()` annotates Workflow nodes with semantic evidence without changing the legacy `to_workflow()` contract.

## Web Time Machine linkage

The Time Machine records relationships among target URL, exact DOM hash, exact response hash/status/content type, selector, Workflow definition hash and Dataset revision ID. It intentionally does not duplicate raw DOM/response bodies into the linkage index. Sensitive URL query values are redacted before persistence.

## Safety / compatibility constraints

- no cloud dependency was introduced;
- non-idempotent replay is not automatic;
- captured credentials are not copied into Workflow candidates;
- the v6.8 approved startup animation was not modified;
- historical `arenyxa` facade/plugin compatibility remains frozen;
- Enterprise Identity/Server work remains outside Phase 2.
