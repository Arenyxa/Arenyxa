# Arenyxa Enterprise Security & Observability Hardening

This increment strengthens operational security without changing the Enterprise trust-domain model,
Distributed Job state machine, or approved startup UX.

## Security invariants

1. **Authentication throttling survives process restart.** Enterprise password failures are stored in
   a separate bounded state file authenticated with an HMAC key derived from the unlocked Vault data
   key. The state contains only opaque username buckets, attempt counts, and cooldown timestamps.
2. **Throttle-state tampering is fail-closed.** Existing state with an invalid schema or MAC is never
   silently reset during login. An authenticated Vault restore transactionally writes a fresh state
   under the restored Vault key.
3. **Remote Worker traffic is bounded before business logic.** The Enterprise Server applies bounded
   per-peer request limits, stricter challenge/auth limits, and a global in-flight request ceiling.
   Attacker-controlled limiter keys are themselves bounded.
4. **Transport failures are diagnosable.** `X-Arenyxa-Correlation-ID` is bounded and sanitized. The
   Server echoes it and structured logs retain it. A leased Job uses `job:<job_id>` across start,
   renew, checkpoint, side-effect, completion, and failure calls.
5. **TLS remains fail-closed for Enterprise Worker transport.** Normal CA verification plus the
   Enterprise-Root-signed Server identity/certificate binding remain mandatory, with TLS 1.2 as the
   minimum protocol level.
6. **Coordinator trust has an explicit hardened mode.** Compatibility mode continues to authenticate
   the ephemeral LAN leaf through the Enterprise-Root-signed certificate binding. Supplying a CA or
   requiring CA validation adds certificate-chain verification *before* the Enterprise identity
   check. No enrollment secret is sent before identity verification in either mode.
7. **No security state is unbounded.** Auth throttle buckets, transport rate-limit buckets, Worker
   challenges/sessions, request bodies, and Distributed transition journals retain explicit limits.

## Intentional compatibility boundary

The Coordinator currently uses ephemeral self-signed LAN certificates by default, so existing Office
Enterprise deployments remain in `enterprise-identity-pinned` mode unless a trusted CA chain is
provisioned. This increment adds `ca+enterprise-identity` capability but does not silently make a
self-signed deployment fail at startup.

A future versioned Enterprise PKI increment should introduce an operational Enterprise Issuing Key
under an offline/rarely-used Enterprise Root and define certificate rotation/migration semantics.
That change is intentionally not folded into this transport hardening because it changes trust
artifacts and compatibility rather than merely strengthening runtime enforcement.
