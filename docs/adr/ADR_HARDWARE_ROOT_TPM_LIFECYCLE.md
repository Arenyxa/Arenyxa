# ADR — Developer Hardware Root TPM lifecycle

## Status

Accepted for Arenyxa v7.7 hardening.

## Decision

Arenyxa Developer Root authority supports a Windows TPM-backed ECDSA P-256 Hardware Root. The public application contains only generic TPM/CNG key-provider primitives and public verification/lifecycle validation. Root provisioning, Root signing, issuer administration, rotation, migration and recovery ceremonies remain in the physically separate Private Developer Authority package.

Hardware Root v3 adds monotonic generation and a SHA-256 digest of the CNG Unique Name so a public Root artifact can be compared with the locally opened TPM key without publishing the platform-specific unique name itself.

The five protection layers are policy boundaries, not five redundant ciphertext wrappers:

1. Microsoft Platform Crypto Provider / TPM-backed KSP;
2. machine-scope persistence;
3. private export policy disabled;
4. signing-only key usage;
5. high-protection UI policy.

The Root private key is never intentionally materialized in Python memory. Signing passes only a SHA-256 digest to the CNG key handle.

## Lifecycle

- **Provision** — creates a new generation-specific persisted key without overwrite semantics.
- **Health proof** — verifies local key policy/binding and signs a bounded challenge-derived proof.
- **Issuer administration** — Hardware Root signs Ed25519 Issuing certificates and Issuing-key revocations; day-to-day Developer/Owner certificates remain below the Issuing tier.
- **Migration/rotation** — requires signatures from both the old Root and the new Root. Generation must advance exactly once.
- **Transition bundle** — packages old/new public Root artifacts plus the dual-signed rotation for an overlap-then-retire-old deployment.
- **Recovery** — private Root export is forbidden. Continuity uses a second Hardware Recovery Root on another trusted TPM and a dual-signed recovery binding.
- **Recovery activation** — only valid within the binding validity window and requires a Recovery Root signature plus incident identifier and nonce.

## Fail-closed rules

- Provider must report a hardware implementation.
- Root keys must be machine-scoped, non-exportable, signing-only and high-protection.
- Existing key-open errors other than key-not-found are not converted into implicit provisioning.
- Failed key creation rolls back the incomplete key handle rather than leaving a partially configured Root.
- Root artifact generation, key-name generation and CNG Unique Name binding must agree.
- Rotation, recovery and health artifacts are canonicalized and cryptographically verified before use.
- Public runtime never performs Root provisioning or Root signing.

## Attestation boundary

Local CNG provider inspection and proof-of-possession demonstrate that the expected Windows Platform Crypto Provider key is present and usable with the configured policy on that machine. This is not equivalent to remote cryptographic EK/AIK attestation.

Classic Windows enterprise TPM key attestation is RSA-oriented. Arenyxa does not label its ECDSA P-256 Root as remotely attested unless a separately verified attestation mechanism is introduced.

## Recovery rationale

A truly non-exportable TPM Root cannot have a conventional private-key backup. Therefore resilience is obtained through pre-authorized multi-root continuity rather than weakening non-exportability.
