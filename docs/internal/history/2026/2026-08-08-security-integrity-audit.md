# Arenyxa V6.0 security, provenance and integrity audit — 2026-08-08

## Scope

This audit used the I18N + Professional Motion Refined source tree as the baseline. It focused on release provenance, anti-tamper behavior, Repair Center trust, project/package parsing, plugin isolation, Marketplace transport, browser-profile paths, settings resilience, and regression safety. The goal is provenance and damage containment without DRM: source/development builds stay editable and modified/community builds remain fully functional.

## High-impact issues fixed

- Replaced unsigned-hash-only release identity with detached Ed25519 release attestations over the installation manifest.
- Moved official trust roots into a compiled module. The external trust store cannot independently create an official identity.
- Added official-build fail-closed checks: supported schema/channel, GPL license identifier, build id, signer id, manifest hash, signature, compiled official key, and optional per-file deep verification.
- Prevented Repair Center from trusting the current installation recovery payload after a release-attestation failure; it must fall back to a previously verified known-good recovery set.
- Prevented source/development edits from being mislabeled as tampering or automatically restored unless strict source integrity is explicitly enabled.
- Bound Repair Plans to the running installation and declared Arenyxa data repair directory, reject unknown plan fields/categories, and write plans atomically.
- Hardened `.arenyxa` packages against undeclared files, duplicate ZIP entries, malformed/oversized manifests, path traversal, symlink entries, invalid checksums and malformed manifest field types.
- Hardened plugin manifests and sandbox invocation. Extra caller permissions are no longer passed to a plugin that did not declare them. Raw `ctypes` now requires the explicit process capability, and file reads/writes are constrained to plugin/runtime/authorized storage roots.
- Fixed Browser Profile ID path traversal and added atomic profile writes plus malformed-profile validation.
- Remote Marketplace catalogs now require HTTPS, HTTPS redirects are checked for both catalog and package downloads, local catalog size is bounded, and catalog/hash structures are validated.
- Fixed settings health scanning for non-object JSON and made settings loading resilient to invalid types/ranges without silently rewriting the original file.
- Improved missing `cssselect` diagnosis so a missing mandatory dependency is not incorrectly reported as an invalid CSS selector.
- Added release provenance to About with localized provenance labels and explicit GPL/provenance separation.
- Replaced the one-line license pointer with the full GPLv3 license text and added distribution/provenance notices.

## Freedom-preserving policy

Arenyxa does not disable features because a build is modified or unverified, does not bind to hardware, does not require online activation, and does not prohibit lawful GPL commercial redistribution. The verified-official state is a cryptographic provenance statement, not a commercial license. This design is intended to make false official claims and silent binary modification detectable while retaining normal GPL freedoms.

## Verification performed

- Python compilation/AST checks across source, tests and build scripts.
- Provenance, project-format, Repair Center, runtime-security and existing non-UI regression tests.
- Manual build-tool validation for Ed25519 key generation and official attestation creation/refusal when the compiled public key does not match.
- Static PowerShell Repair Worker checks, including non-interactive execution and forced known-good recovery after invalid release attestation.

## Environment limitations

The audit container does not contain PySide6, so real Qt GUI/animation smoke tests cannot run here. It also does not contain `cssselect`; Arenyxa declares `cssselect` as a required dependency and Repair Center detects it, but the CSS extraction test cannot execute successfully in this container until that dependency is installed. PowerShell/Windows-specific repair execution was statically checked rather than executed natively in this Linux environment.

## Security boundary

No local anti-tamper mechanism is unbreakable when an attacker controls the machine and has the full open-source code. The design therefore treats cryptographic provenance, safe recovery provenance, explicit modified-build identity, least privilege and transparent licensing as the durable controls rather than pretending to provide absolute DRM.
