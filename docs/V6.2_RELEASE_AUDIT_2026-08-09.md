# Arenyxa V6.2 Release Audit — 2026-08-09

## Baseline

Source baseline: `Arenyxa_V6.1_Unified_Domain_Network_Core_Reviewed.zip` generated from the user-supplied latest V6.0 reliability/stability baseline. V6.2 is an additive capture-enrichment release; it does not rewrite Replay/API Map or remove the legacy `NetworkEvent` compatibility envelope.

## Implemented

### Normalized body storage

- Added `BodyArtifact` to `arenyxa.domain.network`.
- Added `NetworkBodyStore` with a default 2 MiB per-body storage budget.
- Body IDs are stable per capture session + original payload SHA-256.
- Truncated bodies retain both original SHA-256 and stored-prefix SHA-256; `.partial` storage suffix prevents a truncated prefix from masquerading as a complete content-addressed blob.
- Stored payload references are relative to the capture body root and guarded against path traversal on resolution.
- Full stored-body readback verifies exact stored length and stored SHA-256.
- Added `network_bodies` SQLite table and read/quality-metric APIs.

### Browser Capture

- HTTP emission moved to the Playwright `requestfinished` lifecycle so response payload reads occur after successful body download.
- Request body references are persisted when Playwright exposes post data.
- Response body capture is budget-aware: known oversized responses are not materialized; unknown-size body reads are restricted to document/XHR/fetch resources.
- Response-body capture outcome is recorded (`stored`, `stored_truncated`, `empty`, `disabled`, or skipped reason).
- Server address and TLS security details are attached when Playwright exposes them.
- WebSocket open/frame/close events enter the standard Network Core pipeline; text/binary frame payloads use the same Body Store.
- Failed browser requests remain represented as normalized request records with stable error metadata.

### System Capture

- Optional tshark dissector fields are negotiated through `tshark -G fields`; unsupported enrichment fields are not forced into the capture command.
- TCP/UDP stream IDs are used as Flow references where available.
- Process-port correlation now infers inbound/outbound direction and local/remote endpoints when possible.
- `frame.time_epoch` is preserved as event time.
- DNS metadata now uses the canonical Network Core keys (`query_name`, `query_type`, `answers`, `elapsed_ms`), fixing the previous `dns_qname`/`query_name` mismatch.
- TLS SNI, version, cipher and ALPN are projected into `TlsHandshake`/Flow metadata.
- System capture continues to make no claim of decrypting HTTPS payloads.

### HAR

- HAR request `postData` and response `content.text` can be persisted through `NetworkBodyStore`.
- Valid base64 HAR content is decoded before body hashing/storage.
- HAR connection ID, server address and Chromium-style security details are projected when available.
- One-shot HAR import now atomically commits capture summary + legacy events + body metadata + normalized projections through `append_capture_events()`.

### Persistence reliability

`append_capture_events()` now upserts the parent capture row before child network rows inside the same transaction. This allows a one-shot import to be created atomically and removes the previous crash window where a `COMPLETED` capture session could exist without its event rows.

## Migration

V6.2 adds one additive migration after the V6.1 Network Core migration. Existing V6.1 databases receive `network_bodies` through the normal `pre-migration.bak` safety path. V6.0 migration regression coverage was corrected so it actually starts before both the V6.1 and V6.2 migrations rather than accidentally treating the latest-minus-one migration set as V6.0 forever.

## Release/version synchronization

- Package/application version: `6.2.0`.
- Runtime User-Agent defaults: `Arenyxa/6.2`.
- Headless API version: `6.2.0`.
- Windows installer metadata/output name: `Arenyxa_V6.2_Setup_x64`.
- Version-sensitive provenance and packaging tests now derive the current version instead of hardcoding V6.1 fixture strings.

## Verification

Final source-tree test gate:

- `196 passed`
- `3 skipped`
- `1 warning`

The three skipped modules require PySide6, which is not installed in the verification container:

- `tests/test_i18n_motion_refinement.py`
- `tests/test_visual_motion_capture.py`
- `tests/test_ui_smoke.py`

The remaining warning is the intentional duplicate ZIP-entry fixture used to verify project-import rejection behavior.

Targeted V6.2/V6.1 network tests passed before the full gate, including body integrity/truncation, V6.1→V6.2 database migration, V6.0→current migration, HAR body/TLS/connection projection, tshark DNS/TLS/endpoint enrichment, optional tshark field negotiation, and one-shot atomic capture creation.

`python -m arenyxa --version` returned `Arenyxa 6.2.0`.

Wheel build succeeded with the locally installed `setuptools 82.0.1` / `wheel 0.46.3` using `--no-build-isolation`. The first isolated build attempt could not obtain `setuptools>=75` from the execution environment's package index; this was an environment/index limitation rather than a source build failure.

## Environment-limited checks

The Python Playwright package is installed and its current sync API was inspected to verify the methods/properties used by V6.2 (`Request.post_data_buffer`, `Request.timing`, `Request.response()`, `Response.body()`, `Response.server_addr()`, `Response.security_details()`, WebSocket frame events). The verification container does **not** contain the Playwright Chromium binary, so an end-to-end browser launch test could not be completed here. The adapter preserves the existing explicit dependency/browser-install error path.

PySide6 is also absent, so the three Qt visual/smoke suites were skipped rather than reported as passing.

## Next gate

V6.3 should consume normalized `http_requests`/`http_responses` and `network_bodies` for Replay/API Map, while retaining explicit confirmation for side-effecting methods and redaction/secret handling. Capture adapters should not be rewritten again as part of that UI/application-layer migration unless a demonstrated data-quality gap requires it.
