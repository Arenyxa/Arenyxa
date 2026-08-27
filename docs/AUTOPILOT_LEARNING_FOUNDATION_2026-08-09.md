# Arenyxa Autopilot Learning Foundation — 2026-08-09

## Objective

This increment begins the Web Intelligence learning path while keeping core execution deterministic. The design keeps deterministic runtime evidence authoritative, adds bounded local feedback, and creates privacy-preserving training data that can later support small Strategy Ranker, Selector Recovery Ranker, and Failure Classifier models.

## Implemented architecture

`src/arenyxa/application/autopilot.py` adds four production components:

1. **ExperienceStore** — a dedicated SQLite/WAL feedback store at `Arenyxa/intelligence/experience.db`. Strategy and selector outcomes use short transactions, bounded retention, indexed aggregation, and Beta-smoothed priors so a small number of runs cannot overpower live evidence.
2. **AutopilotEngine** — extracts coarse site/runtime features, hashes the hostname into a 24-hex site key, loads local strategy priors, and feeds them into the existing SmartPath 2.0 planner. The resulting plan remains explainable and deterministic.
3. **SelectorRecoveryRanker** — combines the existing DOM heuristic score with bounded historical success priors. It stores selector *categories* (stable attribute / id / text / class / structural) rather than raw selector text.
4. **FailureClassifier** — deterministic classification for rate limiting, authentication/access failures, origin instability, timeouts, TLS failures, selector drift, schema drift, and data-quality regression.

## Privacy boundary

The experience database and training export deliberately do **not** persist:

- complete URLs, paths, or query strings;
- DOM/HTML or response payloads;
- request/response headers;
- Cookie, Authorization, API keys or tokens;
- user prompts;
- raw selectors.

Only hashed site identifiers, coarse boolean/numeric features, selected engine, outcome metrics, failure class, and selector category are retained. No automatic cloud upload exists.

## UI

Intelligence Studio now includes **Autopilot Learning**. It can:

- analyze an authorized URL/capture using SmartPath plus local experience priors;
- show the current plan and historical samples;
- explicitly record a successful or failed outcome;
- show ExperienceStore statistics;
- export a redacted JSONL training dataset into the Arenyxa exports directory.

Feedback is explicit in this first increment. Automatic run-outcome ingestion should only be enabled once task-to-plan attribution is unambiguous, so unrelated runs cannot contaminate the learning data.

## Reliability design

- No model is required to run Arenyxa.
- Historical strategy influence remains bounded by SmartPath's existing history channel.
- Selector history can move a candidate by at most 18 percentage points.
- Strategy success uses a Beta(2,2) prior to reduce overreaction to tiny samples.
- Strategy and selector tables are bounded (default 100,000 rows each).
- Training export uses atomic temp-file + `fsync` + replace.
- Experience data is kept outside the primary user dataset database so experimental learning schema changes do not endanger task/run data.

## Next engineering steps

The intended sequence is:

1. Add reliable automatic attribution from completed Runs to their originating Autopilot plan.
2. Add Shadow Validation records for repaired strategies/selectors.
3. Add cross-site coarse-feature priors without storing hostnames.
4. Accumulate real labelled feedback and build offline benchmark datasets.
5. Only after sufficient data exists, evaluate a small CPU-friendly Strategy Ranker / Selector Ranker. The deterministic engine remains the validator and fallback.

