# Arenyxa v8.0 beta9 — Crawler Phase 1–2 Implementation Report

## Phase 1 — Industrial Crawl Core

Implemented as additive architecture without replacing the existing Crawler Lab UI or extraction stack:

- Stable priority frontier (`PriorityFrontier`)
- Bounded SHA-256 URL deduplication (`UrlDeduplicator`)
- Per-host concurrency and monotonic pacing (`HostRateController`)
- Crawl throughput/statistics primitive (`CrawlStats`)
- Atomic, versioned checkpoint persistence (`CrawlCheckpointStore`)
- Existing robots.txt, scope, extraction, pause/cancel, export and NetworkUseGuard paths preserved
- Existing BFS behavior preserved by assigning discovered URLs depth-derived priorities

## Phase 2 — High-performance Fetch / Session / Proxy Foundation

Implemented:

- Reuses Arenyxa's persistent HTTPX connection pools rather than creating a second HTTP stack
- Existing keep-alive/TCP/TLS connection reuse retained
- HTTP/2-capable transport remains provided by HTTPX negotiation where available
- Health-aware proxy pool with round-robin selection, per-domain affinity, failure scoring and cooldown
- Per-run crawler session policy for default headers and proxy configuration
- gzip plus optional Brotli/Zstandard response decoding with decompressed-size safety bounds
- `Accept-Encoding` advertises only codecs actually available in the runtime
- Existing DLP and NetworkUseGuard egress checks remain on every request
- Retry/Retry-After/backoff behavior remains owned by the hardened HttpFetcher

## Explicit non-claims

HTTP/3 is not marked implemented in this phase. The current HTTPX transport does not provide native HTTP/3; claiming it without a real QUIC transport and qualification tests would be a fake implementation. It should be added through a separately tested QUIC/HTTP3 adapter in a later transport increment.

## Validation

Executed:

`pytest -q tests/test_http_redirect_network_guard.py tests/test_http_resilience.py tests/test_crawler_engine.py tests/test_crawler_phase1_phase2.py`

Result: **22 passed**.

The new Phase 1–2 test module covers priority ordering, bounded deduplication, per-host concurrency, atomic checkpoint format, and proxy cooldown behavior.
