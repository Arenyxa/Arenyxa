# Arenyxa v8.0 beta10 Runtime Hardening Report

This beta10 branch preserves the v8.0 package/protocol compatibility identity while advancing the prerelease channel to beta10.

## DeepSeek beta7 runtime review triage

The supplied beta7 review was checked against the current Phase1-6 tree rather than accepted as current-state truth.

- Clock rollback: already hardened by StableEpochClock, which projects monotonic elapsed time onto persisted epoch deadlines.
- Lease recovery TOCTOU: current recovery already uses fenced conditional UPDATE + rowcount verification.
- DPAPI scope: current implementation already supports user/machine/auto and persists the selected scope envelope.
- SecretBuffer: current implementation already has context-manager zeroization; finalizer is fallback only.
- PostgreSQL: current runtime already has pool metrics/reconnect accounting and retry policy.
- Remaining valid gaps are tracked below and must not be represented as fully hardware/chaos-qualified without Windows/native and fault-injection validation.

## Remaining external/native qualification

TPM/CNG real hardware sealing cannot be truthfully certified from a non-Windows build environment. The adapters remain unavailable unless a real platform provider is injected; beta10 adds explicit downgrade diagnostics/fail-closed policy at DeviceKeyStore selection rather than claiming TPM protection.

Coordinator TLS hot rotation requires live-server/native integration qualification before production certification. Beta10 extends certificate lifetime/expiry observability; automatic socket-context hot replacement remains a separate qualification item rather than a fake implementation.

Full disk, power-loss, NTP/VM suspend, kill -9, network partition, and real PostgreSQL disconnect chaos drills remain required for production certification.

## Startup / splash crash status

The source-launch path keeps the beta9 deep startup diagnostics and the launcher preserves the console on bootstrap failure. Static/startup contract regression passed in this environment. The normal startup handoff, splash geometry, non-blocking animation contract, root-owner startup hardening, and early crash logger were revalidated.

A real Windows GUI launch cannot be truthfully certified in this Linux build environment because no supported Qt binding/Windows desktop session is available. Therefore beta10 marks the source-level startup regression as PASS but Windows physical startup qualification as REQUIRED before calling the splash-crash issue fully closed on target hardware.
