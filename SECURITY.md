# Security Policy

Arenyxa is intended only for systems and websites the user is authorized to collect or inspect.

## Defaults

- Local HTTP services bind to loopback.
- TLS certificates are verified by default.
- Secrets, Authorization, Cookie, token-like values, and passwords are redacted from logs and diagnostics.
- System packet capture is off until explicitly selected. Missing driver/permission is a recoverable error.
- Replay drafts never mutate captured records. POST/PUT/PATCH/DELETE require explicit side-effect confirmation.
- Plugins are disabled until reviewed and granted capabilities. They execute in isolated subprocesses with audit-hook permissions, timeout/output limits, and Windows Job memory limits.
- `.arenyxa` packages exclude secrets and validate paths and SHA-256 before extraction.

## Reporting

Report security issues privately to the project maintainers. Include the Arenyxa version, stable error code, reproduction steps, and a redacted diagnostic summary. Do not include live credentials, session cookies, tokens, personal data, or packet payloads.



## Enterprise Server / Worker

- LAN or server address discovery is never a trust root. Worker clients require HTTPS, normal TLS certificate validation, and an Enterprise-Root-signed Server identity bound to the exact peer TLS certificate SHA-256.
- Worker private keys remain on Worker devices. Login uses a bounded one-shot challenge; Server session and job lease bearer tokens are stored only as SHA-256 digests server-side.
- Lease loss after a non-idempotent side-effect fence has started moves work to `review_required`; it is never automatically repeated.
- Developer Trust and Root Developer platform authority do not satisfy Enterprise data permissions. Release Signing, Developer Identity and Enterprise Root trust remain separate.
- Production multi-machine MITM/partition, Windows Service, firewall and upgrade/rollback validation remain mandatory external release gates.

## Developer Hardware Root lifecycle (v7.7)

The Arenyxa product tree contains only public Hardware Root trust/verification and the generic Windows TPM/CNG provider boundary. Root provisioning, Root signing ceremonies, migration, rotation and recovery remain in the physically separate Private Developer Authority package.

The private Authority uses a machine-scoped Microsoft Platform Crypto Provider ECDSA P-256 key with private-export policy disabled, signing-only usage, and high-protection UI policy. Root artifacts contain only the public point, CNG unique-key binding digest and policy metadata. No Root-private export API exists in either the product or the private ceremony utility.

Hardware Root health proofs are verifier-challenge-bound and freshness-bounded. Root transition requires dual signatures; recovery requires a separately provisioned recovery Hardware Root and a previously committed dual-signed recovery binding. Root-private backup is intentionally not supported.

The private Authority can produce Hardware-Root-signed external checkpoints binding the exact authority-state digest and audit-chain head. Operators should archive these checkpoints independently/off-host. They improve rollback detection but are **not** a TPM NV monotonic counter; rollback to an older valid checkpoint cannot be detected if every independent copy of the newer checkpoint is also lost or replaced.

The current ECDSA P-256 path validates local Windows CNG/TPM provider properties and live proof-of-possession. It does **not** claim remote EK/AIK TPM attestation. No automatic operation clears a TPM, destroys the legacy Root, overwrites an existing Root container, disables Secure Boot/VBS/BitLocker, or irreversibly retires the legacy trust path.
