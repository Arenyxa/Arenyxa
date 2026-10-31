# Arenyxa Phase 7–10 Enterprise Platform Development Increment

Date: 2026-08-12

## Scope

This increment re-hardens Phase 7 and advances Phase 8–10 without entering Phase 11 Enterprise Server/Worker. It preserves the single Core Runtime, the frozen startup visual implementation, the Settings/Personalization separation, and the Developer Trust/Enterprise Trust separation.

## First-run UX correction

Welcome Center is an independent top-level `QDialog` with no Qt parent. It appears after the approved startup handoff, is not present in MainWindow's page stack, and can be reopened from Settings. The MainWindow is only used as a positioning anchor. Selecting an Experience changes presentation/default navigation, never security authority.

## Phase 7 — Local Enterprise Identity re-hardening

- Encrypted, versioned Identity Vault remains the authority store.
- Account/role/password changes increment authorization generation and retire stale authority.
- Last enabled Super Administrator cannot be disabled, demoted, or deleted.
- Phase 8–10 persistent state lives in bounded encrypted Vault extension namespaces; services do not edit the Vault file or SQLite directly.
- A narrow in-memory service-lease mechanism allows Office Coordinator to continue after the initiating human administrator logs out. Service leases are namespace-scoped, audited before publication, not persisted, and revoked on Vault lock/process stop.

## Phase 8 — Enrollment / Device Trust / Domain Lock

Implemented development-grade control plane:

- single-account campaigns and CSV batch member import;
- unique signed one-time Enrollment Credentials;
- campaign revoke and reissue;
- QR-ready enrollment payload export;
- credential binding to Enterprise ID, account, role snapshot, purpose, expiry, nonce and one-time state;
- device-owned Ed25519 identity;
- device-key protector preference order TPM -> CNG -> DPAPI when providers are actually available, with bounded local AES-GCM fallback only for non-Windows/test environments;
- Domain Lock enabled by default;
- explicit, time-bounded allow-once path before cross-Enterprise device-key rotation;
- transactional device-key preparation/rollback when remote enrollment fails;
- strict JSON duplicate-key rejection and bounded artifacts;
- device registry/revocation and authorization-generation validation.

No client-provided role can override the signed credential. Enrollment codes are not long-lived login credentials.

## Phase 9 — Office Enterprise Coordinator

Implemented secure Office Coordinator runtime foundation:

- standalone `scripts/office_coordinator.py` / PowerShell launcher;
- Desktop is management UI; Coordinator can run as a distinct process;
- Enterprise-Root-signed Coordinator identity bound to the exact ephemeral TLS certificate SHA-256;
- client verifies signed identity on the same TLS connection before sending Enrollment secret;
- TLS 1.2+;
- one-shot nonce-based device challenge authentication;
- device-auth sessions are bounded and authorization-generation aware;
- disabling/changing the backing account invalidates subsequent session validation;
- Coordinator uses only a narrow audited in-memory Vault service lease after startup, not a long-running human administrator session;
- bounded challenge/session maps, bounded HTTP worker threads, request-size bounds and per-peer request-rate bounds;
- LAN discovery metadata contains no Enrollment secret and is explicitly non-authoritative;
- explicit offline policy: no new authentication when Coordinator is unavailable;
- migration model keeps durable identity/device/governance state in the authenticated Enterprise Vault; Coordinator TLS/signing identity is ephemeral, so migration never exports a Coordinator private key;
- device stores only verified Coordinator endpoint/root binding, never a Coordinator bearer session token.

Real office LAN/ARP/MITM behavior still requires Windows/network-lab validation before Phase 9 can be frozen as an operator baseline.

## Phase 10 — Enterprise Workspace Governance

Implemented governance control-plane foundation:

- Workspace and Team objects;
- Project/Workflow/Dataset/Capture/Schedule/Worker governed resource registry;
- owner, team, scope, retention and quota metadata;
- private/team/workspace/enterprise resource scopes;
- role-scoped resource grants in addition to global capability checks;
- team-scoped resources deny same-role users who are outside the assigned team;
- quota admission/reservation and bounded quota telemetry;
- high-risk change approval with requester/approver separation;
- approval requester binding and one-shot consumption when an operation is authorized;
- filtered hash-chain-verified Audit Query;
- Operations Dashboard summary combining governance/quota state with Coordinator and Resource Governor status in the UI;
- `authorize_operation()` is the explicit backend integration boundary for governed runtime callers.

The governance control plane is implemented, but this increment does **not** claim every historical Workflow/Dataset/Capture/Schedule execution entry point has already been migrated to call `authorize_operation()`. That broader runtime wiring remains an integration gate before Phase 10 is considered fully frozen.

## Explicit non-goals

- No Phase 11 Enterprise Server / Distributed Worker authority migration.
- No second Core Runtime.
- No AD/LDAP/OIDC/SAML suite.
- No trust based on LAN location, host name, Enterprise display name or discovery packets.
- No Developer Trust to Enterprise permission conversion.
- No Root Developer customer-data bypass.
