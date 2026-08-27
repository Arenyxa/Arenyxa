# Arenyxa V6.1 — Unified Domain Model & Network Core

## Scope

V6.1 keeps the existing `NetworkEvent` ingestion envelope for compatibility, while introducing a normalized, deterministic network domain underneath it. The intent is to stop treating Browser/HAR/System/HTTP captures as isolated features and make them projections into one core data model.

## Added domain entities

- `Project` and `ProjectSource` for workspace-oriented ownership of collection sources.
- `NetworkFlow` for transport/session aggregation.
- `HttpRequestRecord` / `HttpResponseRecord` for stable request/response identity.
- `DnsTransaction`, `TlsHandshake`, `WebSocketChannel`, and `WebSocketMessage`.
- `NetworkNormalizer` as the backwards-compatible translation boundary from legacy capture events.

## Persistence

A new additive SQLite migration creates project/source bindings, a projection ledger, and normalized network tables. `append_network_events()` and `append_capture_events()` now persist the legacy event and normalized projections in the same database transaction, preventing a crash window where the UI event exists but Replay/API Map cannot find the normalized request.

## Compatibility contract

Existing capture adapters, filters, HAR import, Network UI models, and code consuming `NetworkEvent` remain valid. Historical V6.0 event rows can be projected with the idempotent `backfill_network_core()` path; `network_core_backlog()` exposes remaining work without silently mutating data during reads. The new model is additive. Future V6.2/V6.3 work should consume normalized HTTP exchanges first and fall back to legacy event projection only for imported/older databases.

## Next gates

1. V6.2: enrich capture adapters with DNS/TLS/WebSocket metadata and normalized body storage references.
2. V6.3: move Replay and API Map to normalized request identities, then add request mutation/history/comparison.
3. V6.4: connect normalized requests/responses to Dataset revisions and data-lineage edges.
