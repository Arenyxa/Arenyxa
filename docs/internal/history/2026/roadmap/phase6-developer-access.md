# Phase 6 — Official Developer Access

Phase 6 separates the public Developer Profile from cryptographically authenticated Official Developer Access.

## Trust boundary

- Public Developer Profile remains a presentation/development convenience and cannot authorize internal stress/fault-injection capability.
- Official Developer authentication requires a signed Developer Certificate/Entitlement and proof of the matching device-local Ed25519 private key.
- Runtime JSON is not a Developer Root trust source. Official builds pin only public Developer Root artifacts into `developer_trust_anchors.py`.
- The public source tree intentionally ships with zero trusted Developer Roots, so Official Developer Access is fail-closed until the Root Owner performs the offline ceremony and explicitly embeds a public trust artifact.
- Root Owner routine authentication never uses the Developer Root private key. The private Authority issues a dedicated Owner Authority certificate from an Issuing Key; the Owner device proves its own local Ed25519 private key with a short-lived one-shot challenge. Root remains reserved for Issuing-key administration and offline recovery.
- Developer Trust cannot satisfy Enterprise permissions.

## Internal capability gates

`runtime.debug`, `profiler`, `stress_test`, `fault_injection`, `internal_logs`, and `release.verify` are exact capabilities; no wildcard/all capability exists. Stress tests require Official `stress_test`; standard/extreme require explicit high-risk confirmation. Fault injection requires Official `fault_injection` and is synthetic-only.

## Reliability rules

Challenges are bounded, short-lived and one-shot. Session publication is transactional with mandatory audit persistence. Login/logout cycles retire ephemeral identities/revocation state instead of growing state without bound.
