# Phase 4 — Security Foundation

This phase introduces UI-independent security primitives without creating Enterprise IAM UI.

## Invariants

- `TrustDomain.PERSONAL`, `TrustDomain.DEVELOPER`, and `TrustDomain.ENTERPRISE` are non-interchangeable.
- Experience/Profile selection is presentation and defaults only. It never grants authority.
- Protected backend operations use `SecurityKernel.authorize()/require()/execute()`; hiding a menu is never authorization.
- Policy evaluation is default-deny and explicit-deny overrides allow.
- Sessions are bounded by identity/device generation, revocation and expiry.
- Audit is append-only/hash-chained and fails closed on an already-corrupted chain.
- DPAPI is the Windows software-backed adapter; CNG/TPM are fail-closed adapter boundaries until a real provider is provisioned.
- No Developer capability automatically becomes an Enterprise permission.
- Root Developer / Root Authority is the highest Arenyxa *platform engineering* authority, but it is not a universal customer Enterprise data key. Enterprise business-data access still requires explicit customer authorization and audit.
- Release Signing Trust, Developer Trust and each Enterprise Trust remain separate roots.

The current headless API has been migrated from direct role checks to the unified SecurityKernel. `WorkspaceRole` remains a compatibility input that is translated to Personal-domain capabilities; the authorization decision itself is made by the security kernel.
