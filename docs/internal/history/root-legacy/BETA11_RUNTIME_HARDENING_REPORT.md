# Arenyxa v8.0 beta11 Runtime Hardening Report

## Scope

beta11 is an incremental hardening release on top of beta10 / Crawler Phase 1–6. It preserves the v8.0 package identity (`8.0.0`) and plugin/runtime compatibility (`6.8.0`) while advancing the prerelease channel to `beta11`.

This release specifically addresses the remaining high-value items identified from the beta7 production-runtime review: storage-aware adaptive control, distributed-storage circuit breaking, stale-Worker lease recovery, Coordinator TLS certificate hot rotation, and truthful TPM-backed key protection.

## Implemented fixes

### 1. Storage-aware adaptive request control

- Added bounded SQLite write-latency telemetry and WAL pressure observation.
- Added write busy/failure counters and approximate WAL page pressure.
- `_AdaptiveRequestController` now receives storage pressure as a separate causal signal.
- Storage pressure no longer causes parser/CPU-style request-concurrency backoff.
- Result persistence batching grows under write pressure and recovers toward the configured baseline when storage becomes healthy.
- Storage lock/busy failures are surfaced as `RUN_STORAGE_BACKPRESSURE` rather than being indistinguishable from generic run failure.

### 2. Distributed SQLite storage circuit breaker

- `lease_next()` and `lease_many()` now distinguish a genuinely empty queue from storage failure/backpressure.
- Consecutive storage failures produce `DISTRIBUTED_STORAGE_BACKPRESSURE` and then open a bounded circuit with `DISTRIBUTED_STORAGE_CIRCUIT_OPEN`.
- Circuit state, consecutive failures, retry delay, and redacted last-error state are exposed through distributed health telemetry.
- A successful half-open probe closes the circuit and clears the failure streak.

### 3. Worker heartbeat driven phantom-lease recovery

- Added `recover_stale_worker_leases()` using the stable monotonic-projected epoch clock.
- Active leases can be recovered before their full lease deadline when the owning Worker heartbeat has disappeared beyond the configured threshold.
- Idempotent work is requeued under fencing.
- Non-idempotent work whose side effect has started is moved to `review_required`; it is never automatically executed again.
- Existing lease-token fencing prevents a stale Worker from completing a recovered/reassigned job.
- Startup reconciliation now includes stale-Worker lease recovery.

### 4. Coordinator TLS certificate hot rotation

- Certificate lifetime remains seven days with a 24-hour renewal window.
- Added an automatic TLS identity maintenance thread.
- Implemented live certificate rotation without stopping the Coordinator listener.
- The listener keeps a stable dispatcher `SSLContext`; the TLS handshake callback atomically selects the current certificate context for each new connection.
- Existing accepted TLS sessions keep their old context and continue uninterrupted.
- Context-specific signed identity artifacts are retained for active keep-alive generations so the identity endpoint remains certificate-bound during rotation.
- Health now exposes TLS rotation status, failure details, and rotation count.
- `X-Arenyxa-Cert-Expiry` remains exposed to clients.

### 5. TPM-backed key protection authenticity

- `TPMKeyProtectionAdapter` no longer relies only on injected callbacks.
- On Windows it can use the real `Microsoft Platform Crypto Provider` through `ncrypt.dll`.
- Hardware-backed provider status is checked through CNG implementation properties.
- A non-exportable RSA wrapping key is persisted in the TPM provider.
- Protected values use a fresh AES-256-GCM data key; the data key is wrapped with TPM RSA-OAEP/SHA-256.
- Existing TPM wrapping keys are validated for non-exportability and decrypt usage before use.
- Failed TPM-key creation performs best-effort persisted-key rollback and emits a critical diagnostic if rollback itself fails.
- `ARENYXA_TPM_SCOPE=auto|user|machine` controls TPM key persistence scope; service runtime defaults to machine scope in `auto` mode.
- The adapter never claims TPM availability when the hardware provider or native sealing path is unavailable.
- `ARENYXA_REQUIRE_TPM` remains fail-closed.

## Preserved beta10 fixes

- Host-first request admission remains in place.
- Stable monotonic-projected lease time remains in place.
- Conditional terminal updates and non-idempotent side-effect fencing remain in place.
- DPAPI `auto|user|machine` scope remains in place.
- `SecretBuffer` deterministic context-manager zeroization remains in place.
- Deep startup diagnostics and splash/main-window handoff protections remain in place.
- Crawler Phase 1–6 remains present.

## Verification performed in this build environment

- Focused beta11/runtime/crawler/distributed/startup regression set: **151 passed, 1 skipped, 0 failed**.
- The skip is the expected Qt-dependent startup visual test because this Linux CI environment has no supported Qt desktop binding.
- Python compile validation: **PASS**.
- v8.0 release identity gate: **PASS** (`display=8.0`, `package=8.0.0`, compatibility `6.8.0`).
- New beta11 runtime tests cover adaptive storage causality, storage circuit behavior, stale heartbeat lease recovery, non-idempotent review fencing, live Coordinator TLS rotation, and TPM no-false-claim behavior.

## Existing repository-wide quality debt not introduced by beta11

A clean beta10 baseline comparison confirms these values were already present before beta11:

- broad `Exception` catches: beta10 **284**, beta11 **284** (unchanged; repository ratchet target is 261).
- partially typed functions: beta10 **104**, beta11 **104** (unchanged; repository ratchet target is 101).
- `BaseException` catches: beta10 **9**, beta11 **5** (improved to the current test ceiling).

Accordingly, the repository-wide architecture-debt ratchet still reports failure for the pre-existing broad-Exception count, and the code-quality ratchet still reports failure for the pre-existing partially-typed count. These are not represented as beta11 runtime-fix failures and were not hidden by weakening tests.

## Physical/native qualification still required

The following claims require the target Windows environment and are intentionally not marked as physically certified in this Linux build environment:

- real Windows Qt splash-to-main-window launch on the target workstation;
- real TPM 2.0 protect/unprotect against Microsoft Platform Crypto Provider hardware;
- Windows service/machine-scope TPM persistence across service-account lifecycle;
- long-duration (>7 day accelerated/soak equivalent) Coordinator rotation under real clients;
- disk-full, SQLite device-I/O saturation, real network partition, kill-9/process termination, and PostgreSQL server restart chaos testing.

The code paths and deterministic regression tests are present; physical qualification remains a release-environment gate rather than a simulated claim.
