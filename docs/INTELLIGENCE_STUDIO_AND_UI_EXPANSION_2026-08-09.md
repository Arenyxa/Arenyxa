# Arenyxa V6.0 — Intelligence Studio & UI Expansion Audit

Date: 2026-08-09

## Implemented feature families

- Selector Studio: stable CSS/XPath candidates, fingerprints, confidence scoring and self-healing.
- Browser Recorder 2.0: action normalization, live bounded Playwright recording, password-value exclusion, Workflow conversion, Python/JavaScript Playwright generation and headless replay.
- HTTP Request Builder: headers/query/cookies/body/TLS/proxy/timeouts/retry, variable substitution, safe pre-request action DSL, response assertions and code generation for curl/requests/httpx/fetch/axios/PowerShell/Playwright.
- Protocol Inspector: GraphQL operation grouping, WebSocket frame metadata and SSE detection.
- Data Source Discovery + SmartPath 2.0: DOM, JSON, Next.js, Nuxt, JSON-LD and captured API source ranking with execution-engine recommendations.
- Adaptive request control: per-host backoff/recovery plus a live global request-submission budget.
- Data Quality Studio: schema inference, duplicate/missing/outlier scoring and deterministic cleaning/coercion/default/dedup operations.
- Secrets Vault: encrypted local storage; Windows key protection uses DPAPI; secret values are excluded from project environment files and distributed-worker metadata.
- Project environments: isolated project directories, environment metadata and per-project Python .venv creation/install/freeze tools.
- Workflow debugging: breakpoints, step/continue/retry primitives and production WorkflowEngine scoped-variable/secret resolution.
- Templates & Marketplace: built-in templates, project materialization, HTTPS-only remote catalogs/packages and SHA-256 package verification.
- Browser Profiles: profile metadata, proxy/user-agent/locale/timezone and secret references with safe metadata export.
- Distributed Workers: opt-in authenticated Arenyxa Headless Server registry, health/task/run calls, TLS requirement for non-loopback workers and weighted partition preview; no arbitrary remote shell.
- Activity Center: bounded thread-safe runtime event journal spanning runs, captures, selectors, HTTP, workers, templates and data quality actions.

## UI / shell integration

- New Intelligence Studio entry in the Advanced navigation group.
- Quick Studio button in the top bar.
- Ctrl+Shift+I opens SmartPath; Ctrl+Shift+H opens HTTP Request Builder.
- Command Palette exposes SmartPath, Selector Studio, HTTP Builder, Live Center, Secrets, Recorder, Debugger, Profiles/Marketplace and Distributed Workers.
- Top-bar compact live progress reflects run/capture state.
- Windows taskbar progress uses normal/paused/error/indeterminate states when available and degrades to a no-op elsewhere.
- System tray provides Open Arenyxa, Intelligence Studio, Live Run Center, Network Capture and Exit actions.
- Intelligence Studio expensive work uses the shared background executor so the Qt event loop is not deliberately blocked.

## Security boundaries

- The HTTP pre-request feature uses an auditable action DSL instead of silently evaluating arbitrary source code.
- Distributed workers use existing token-authenticated Arenyxa REST endpoints; tokens remain in Secrets Vault. Non-loopback plain HTTP endpoints are rejected.
- Browser live recording excludes password values and is time-bounded.
- Project Python package installation is explicit and requires a user confirmation in the UI because third-party packages can execute installer code.
- Marketplace downloads require HTTPS and package SHA-256 verification.
- Activity events are intended for identifiers/counts/redacted metadata, not secret payload persistence.

## Validation limits

The source is compile-tested and non-GUI tests are run in the review environment. Full PySide6 GUI smoke, Windows taskbar COM behavior, real Windows tray behavior, Playwright Chromium live recording and Inno/PyInstaller output require the declared Windows/GUI/browser build environment and are final release-gate items.

## Final review evidence

- Python `compileall`: PASS for `src` and `tests`.
- Non-GUI regression suite: **150 passed**, with one intentional Python `zipfile` duplicate-entry warning from the Zip-Slip/duplicate-entry rejection test.
- New Intelligence Studio suite: **14 passed** (included in the 150 total).
- Source Repair manifest: **72/72 protected files matched**; recovery seed SHA-256/size matched and ZIP CRC passed.
- Source manifest: **141/141 entries matched** after the final source changes.
- Wheel packaging: `arenyxa-6.0.0-py3-none-any.whl` built successfully with `pip wheel --no-build-isolation --no-deps` in the review environment.
- Legacy pre-Arenyxa brand-string scan over text source: no remaining matches.
- Full PySide6 GUI/offscreen tests were not executed in this container because PySide6 is not installed here. The package declares PySide6 as a runtime dependency; the Windows build pipeline remains the release gate for GUI, tray, taskbar COM, PyInstaller and Inno Setup behavior.
- Real interactive Playwright recording was not launched in this container because the optional Playwright/Chromium browser runtime is not installed; conversion, validation and service contracts are covered by unit tests.
