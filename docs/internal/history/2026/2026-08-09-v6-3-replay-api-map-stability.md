# Arenyxa V6.3 — Replay + API Map & Stability Audit

Date: 2026-08-09

## Scope

V6.3 is the first release that consumes the normalized V6.1/V6.2 HTTP Exchange and Body Ref model as the authoritative source for API discovery and Request Replay. The change intentionally leaves capture adapters backward-compatible while moving higher-level tooling away from adapter-specific transient state.

## API Map v2

- Deterministic endpoint IDs from method/scheme/host/path-template.
- Numeric, UUID, long hexadecimal and ULID path segments are normalized to stable placeholders.
- Query parameter presence, type hints, examples and pagination candidates are profiled.
- Status distribution, success rate, request/response MIME types and authentication *signals* are recorded without credential values.
- GraphQL likelihood is derived from route and bounded request-body inspection.
- JSON response schema inference is bounded by per-body and snapshot-wide byte budgets plus depth/key limits.
- Snapshots and endpoint definitions are written atomically to SQLite.

## Replay v2

- Replay drafts can be created directly from normalized HTTP Exchanges.
- Request Body Refs are resolved only through the canonical capture root and verified against stored size/SHA-256 metadata.
- Bounded partial reads are considered incomplete and are never treated as replay-safe complete bodies.
- Hop-by-hop headers and captured Content-Length/Host are removed before replay.
- Authorization, Cookie, proxy authorization and token/API-key-like headers become explicit Secret references instead of silently replaying captured plaintext.
- Anonymous replay is an explicit transformation that drops unresolved secret-bearing fields.
- POST/PUT/PATCH/DELETE retain a side-effect confirmation gate.
- Truncated request bodies are rejected by default.
- CancellationToken is preserved through replay execution; cooperative cancellation is recorded distinctly from failure.
- Response comparison includes status, media type, body hashes/sizes, timing delta, bounded JSON path diff and non-volatile header changes.
- Replay persistence stores redacted request metadata and response hashes/metadata rather than duplicating response bodies.

## Stability hardening

- V6.2 databases receive additive V6.3 tables through an atomic migration with the existing pre-migration backup path.
- Corrupt normalized HTTP JSON now raises stable `NETWORK_CORE_CORRUPT` errors with request/field context.
- Replay persistence validates optional capture/request foreign keys and safely nulls stale references rather than failing an otherwise valid audit record.
- API Map analysis is bounded to 100,000 exchanges by default and has explicit schema memory/byte limits.
- Existing V6.1/V6.2 Network Core and capture compatibility paths remain in place.

## Release gate

The release gate covers new V6.3 API Map/Replay tests, V6.1/V6.2 network/database/HTTP regression tests, the complete non-UI suite, source manifest/repair payload regeneration, package build, and final ZIP re-extraction verification.
