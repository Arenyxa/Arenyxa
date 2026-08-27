# Phase 7 — Local Enterprise Identity

Phase 7 implements only the single-machine Enterprise authority required before LAN/Enrollment work.

## Identity Vault

The local Identity Vault is versioned and authenticated-encrypted using AES-256-GCM. A random data key encrypts the payload; a scrypt-derived key wraps the data key. Account passwords use independent salted scrypt verifiers and are never reversibly stored. The Enterprise Ed25519 Root private identity is contained only inside the encrypted Vault payload.

Durable writes use same-directory atomic replacement. The unlocked handle cryptographically binds the passphrase-wrapped envelope so an external replacement cannot be silently preserved by a later save. Failed persistence restores the prior live state. If a mutation commits to the Vault but mandatory audit append fails, Arenyxa attempts a durable rollback; if rollback itself fails, the live Enterprise session is retired and the Vault is locked fail-closed.

## Local authentication and RBAC

The initial account is Local Super Administrator. Roles resolve to permission/capability sets, but backend authorization always passes through SecurityKernel with TrustDomain.ENTERPRISE and the local-enterprise resource context. UI visibility is not authority.

Wrong-password attempts use bounded exponential rate limiting. Sessions are time-bounded and bind `auth_generation`. Disable, role change and password change increment the account generation and revoke an active matching session immediately. The last enabled Super Administrator cannot be disabled, demoted, or deleted. Custom role permission sets are restricted to the Enterprise permission catalog; changing an assigned custom role increments affected account generations so existing sessions cannot retain stale authority.

High-risk governance operations require recent step-up authentication. Vault restore is permitted only while locked. Backup refuses the live Vault path and backup metadata/audit commit is transactional so an unaudited backup operation cannot masquerade as a completed governed action.

## Explicitly deferred

Phase 7 does not implement LAN discovery, Coordinator, Enrollment Credential, Device Trust, Domain Lock, AD/LDAP/OIDC/SAML, or distributed Server/Worker authority. The Welcome Center exposes only the now-real local Enterprise administration path; Join Enterprise remains disabled until Phase 8.
