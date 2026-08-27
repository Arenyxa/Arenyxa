# ADR: v7.8 Async I/O and Capability Layers

**Status:** Accepted for Arenyxa v7.8.

## Decision

Use asyncio/HTTPX AsyncClient as the modern high-I/O request data plane while retaining the existing Future-based run lifecycle contract. Keep bounded threads only at explicit blocking compatibility boundaries. Reuse pooled HTTP connections. Treat desktop, analysis, browser, capture, server, database, and telemetry stacks as optional capabilities.

## Consequences

- High socket concurrency no longer scales one Python request thread per socket in the modern run path.
- Existing Qt, persistence, cancellation, and extension APIs retain compatibility.
- Legacy Windows remains isolated and feature-frozen.
- Minimal source installs no longer require PySide6, Playwright, PostgreSQL drivers, or capture integrations.
- Async code must preserve DLP, SSRF/network guard, response-size, retry, cancellation, and host-fairness invariants.
