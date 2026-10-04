# Arenyxa v8.0 beta12 — Crawler / Scrapling-Parity Engineering Report

## Scope

beta12 is an incremental release on top of beta11. It preserves the v8.0 display/package/runtime compatibility identity while advancing the prerelease channel to `beta12`.

The goal of this change set is to close the previously identified *normal web-crawling* feature gaps while preserving Arenyxa's network-governance, distributed-runtime, recovery, security, and startup hardening.

## Implemented in beta12

### Real optional HTTP/3 transport

- Added `arenyxa.infrastructure.http3_client.Http3Fetcher` backed by `aioquic` when the optional crawler dependency is installed.
- HTTPS-only, bounded response size, redirect bound, TLS verification, cancellation checkpoints, and explicit proxy unsupported behavior.
- `CrawlerTransport` now supports `http3_mode = off | prefer | require`.
- `prefer` fails back to the existing governed HTTP stack when HTTP/3 is unavailable; `require` fails closed.
- No browser/TLS fingerprint impersonation is performed.

### Remote CDP browser support

- `BrowserEngineConfig.remote_cdp_url` and bounded CDP headers.
- Supports Playwright `connect_over_cdp` for `http(s)://` and `ws(s)://` endpoints.
- Remote endpoint host is checked through `NetworkUseGuard` before connection.
- Existing BrowserPool, session affinity, XHR/fetch/WebSocket observation and DOM limits remain in force.

### Async API

- Added `AsyncCrawlerEngine` and `AsyncBrowserPool` using bounded thread handoff to preserve the mature synchronous runtime semantics.

### Spider templates

- `Spider`
- `CrawlSpider`
- `SitemapSpider`, including bounded same-origin sitemap-index recursion
- `XMLFeedSpider`
- `CSVFeedSpider`
- conservative `ShopifySpider.storefront()` template for public storefront crawling

All templates reuse `CrawlerEngine`, `NetworkUseGuard`, robots.txt behavior, retry bounds, and existing transport governance.

### Development cache / replay

- Atomic file-backed crawler response cache.
- `off | read | write | read-write` modes.
- TTL and entry/body limits.
- GET/HEAD only.
- Request headers/cookies are never persisted; only one-way hashes contribute to the cache key.
- Sensitive response headers such as Set-Cookie and authorization-like fields are redacted in metadata.

### XML export

`CrawlerResultExporter` now supports XML in addition to JSON, JSONL/NDJSON, CSV and XLSX.

### DNS-over-HTTPS resolver

- Added an RFC 8484 resolver using dnspython.
- Resolver endpoint is governed by `NetworkUseGuard` and returned addresses are checked against Arenyxa network policy.
- This is a crawler resolver/diagnostic capability; beta12 does **not** claim that every underlying third-party transport has zero OS-DNS leakage.

### Configurable domain blocking

- Crawler scope supports bounded blocked-domain/domain-glob rules.
- Browser routing supports the same concept and aborts configured subresources before navigation.
- No hidden or automatically downloaded blocklist is installed.

### MCP

- Added optional `arenyxa-crawler-mcp` entrypoint using MCP FastMCP when the `mcp` extra is installed.
- Exposes bounded crawler fetch, bounded crawl, governed browser render, and DoH lookup primitives.
- NetworkUseGuard and crawler bounds remain active.

### Adaptive selector release benchmark

- Added deterministic `AdaptiveSelectorBenchmark` plus `scripts/benchmark_adaptive_selector.py`.
- Gate: recovery >= 95%, false-match <= 1%.
- Current deterministic mutation suite: 10/10 recovered, 0 false matches (100% / 0%).
- Selector healing was strengthened to treat exact normalized element text as a strong semantic identity signal while retaining unique-match/confidence policy gates.

### Anti-bot diagnostics and safe adaptation

- Explicit CAPTCHA/human-verification detection.
- Explicit generic anti-bot challenge detection (`BOT_CHALLENGE_PRESENT`).
- HumanVerificationCoordinator creates opaque, expiring operator-review tickets; target URLs are represented only by SHA-256 in tickets.
- AntiBotHostGovernor applies per-host Retry-After/exponential backoff for 429, service-unavailable, and request-rejected states.
- Crawler can optionally use BrowserPool for pages that merely require JavaScript rendering.
- CAPTCHA and explicit anti-bot challenges remain operator-gated and are **not** automatically solved or bypassed.

### Client profile consistency

- Explicit User-Agent / Accept / Accept-Language fields remain supported.
- Reserved headers cannot be silently overridden through `extra_headers`.
- Browser-compatible locale/User-Agent settings can be derived from a profile.
- No browser fingerprint or TLS fingerprint spoofing is claimed.

### Crawler Lab UI

The desktop Crawler Lab exposes:

- HTTP/3 Off / Prefer / Require
- response cache mode and cache directory
- blocked domain patterns
- JavaScript-required Browser fallback
- Remote CDP endpoint
- XML export

## Deliberately not implemented

The following were requested as part of "skip human verification / anti-bot" behavior but are intentionally not implemented:

- CAPTCHA / reCAPTCHA / hCaptcha / Turnstile automatic solving or bypass
- browser-fingerprint spoofing intended to defeat anti-bot controls
- TLS-fingerprint impersonation intended to evade detection
- stealth identity forgery / access-control circumvention

beta12 instead detects these conditions, backs off, records evidence, and requires operator intervention where human verification/access control is present.

## Validation evidence

Focused beta12 + crawler + distributed + Web Intelligence + startup regression set:

- `129 passed`
- `1 skipped`
- `0 failed`
- skip reason: no supported Qt binding in the current execution environment for one physical UI-motion test.

Release identity gate:

- display: `8.0`
- package: `8.0.0`
- plugin/runtime compatibility: `6.8.0`
- prerelease channel: `beta12`

Adaptive selector deterministic benchmark:

- cases: `10`
- recovered: `10`
- recovery rate: `100%`
- false matches: `0`
- false-match rate: `0%`
- gate: `PASS`

Repository collection after beta12 additions: **1351 tests collected successfully**. A complete all-test execution exceeded the current execution time window before completion; no claim of an all-suite PASS is made from that partial run.

## Existing repository-wide debt not hidden by beta12

The existing quality ratchets remain visible rather than being weakened:

- broad `Exception` catch debt remains above the historical architecture ratchet target (latest observed: 281 vs target 261).
- partially typed function count remains above its historical target (104 vs target 101).
- `src/arenyxa/app.py::main` remains above its historical hotspot length target (281 vs 220).

These are pre-existing repository-wide debt items and were not introduced by the beta12 crawler parity modules. beta12 does not change those tests to manufacture a green result.

## Runtime qualification limitations

The current environment does not have `aioquic` or MCP installed, so beta12 validates optional-dependency absence/fail-closed behavior and compiles those implementations, but cannot claim a live external HTTP/3 handshake or live MCP interoperability test in this environment.

Likewise, Remote CDP code is implemented and configuration-validated, but a real remote Chromium endpoint was not available in this execution environment. Windows/Qt physical startup and browser runtime qualification should remain part of the existing native QA process.
