# Arenyxa V6.2 — Network Capture Enrichment

## Scope

V6.2 is the capture-quality release that sits between the V6.1 normalized Network Core and the planned V6.3 Replay/API Map migration. The compatibility contract remains unchanged: adapters continue to emit `NetworkEvent`, while accepted events are projected into normalized Flow/HTTP/DNS/TLS/WebSocket entities in the same SQLite transaction.

## Body reference pipeline

- Added `BodyArtifact` to the normalized network domain.
- Added `NetworkBodyStore`, a bounded content-addressed local payload store.
- Payload records carry both original and stored SHA-256 values so truncated captures remain verifiable without pretending that a prefix is the complete body.
- Storage references are capture-relative rather than absolute host paths.
- Each body records original/stored byte counts, MIME type, encoding, truncation and sensitivity state.
- Body files use atomic replacement and restrictive POSIX permissions where supported.
- Readback validates expected stored length and stored SHA-256 before returning a complete stored artifact.

## Browser Capture

- HTTP events are emitted on `requestfinished`, after the response body is complete.
- Request bodies are persisted through Body References when available.
- Response body capture uses a bounded budget; known oversized responses are not materialized by Playwright.
- Unknown-size body capture is restricted to high-value document/XHR/fetch resources.
- Server address and TLS security details are attached when Playwright exposes them.
- WebSocket open, sent-frame, received-frame and close lifecycle events now enter Network Core; frame payloads use the same Body Reference path.
- Failed requests remain visible as HTTP request records with stable error metadata.

## System Capture

- tshark optional field negotiation prevents a newer field list from making capture unusable on an older packet-analysis runtime build.
- TCP and UDP stream IDs are normalized into stable Flow references.
- Process-aware direction inference maps local and remote endpoints when possible.
- Packet epoch timestamps are preserved rather than being replaced with writer time.
- DNS query name/type, A/AAAA answers and latency are mapped to `DnsTransaction`.
- TLS SNI, version, cipher and ALPN are mapped to `TlsHandshake` and Flow metadata.

## HAR import

HAR import now optionally persists request `postData` and response `content.text` through the same bounded Body Store, including valid base64 content. Connection ID, server IP and Chromium-style security details are projected when present.

The one-shot HAR commit path was also hardened: capture summary, legacy events and normalized projections are committed atomically instead of leaving a crash window between a `COMPLETED` session row and its event rows.

## Database migration

The additive V6.2 migration adds `network_bodies` without rewriting existing V6.1 normalized tables. A V6.1 database receives the new table through the standard pre-migration backup path. Existing V6.0/V6.1 event rows remain readable and backfillable.

## Explicit non-goals

V6.2 does not yet migrate Replay or API Map to normalized request/body identities. That is the V6.3 gate. It also does not claim browser-level DNS visibility where Playwright does not expose DNS transactions, nor does system packet capture claim to decrypt HTTPS payloads.
