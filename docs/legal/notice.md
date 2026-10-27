# Arenyxa distribution notice

Arenyxa is distributed under **GNU GPL-3.0-or-later**. See `LICENSE` for the complete GPLv3 text.

The GPL permits use, study, modification, redistribution, and commercial distribution. A distributor who conveys GPL-covered binaries must satisfy the applicable GPL obligations, including preserving license notices and providing corresponding source in the manner required by the license.

Arenyxa release provenance is separate from copyright licensing:

- **Verified official build** means the release manifest is signed by an Ed25519 public key embedded as an official trust anchor in that build, and the checked installation matches the signed manifest.
- **Verified community build** means a cryptographically verified third-party/community signer is recognized, without claiming official provenance.
- **Modified build** means installed files no longer match the signed release identity.
- **Unverified distribution** means no trusted release proof is available. It is not automatically unsafe and remains usable.
- **Source/development build** is intentionally mutable and is never forcibly restored merely because the developer edits source code.

No provenance state disables normal Arenyxa features. The system is designed to prevent misleading provenance claims, not to impose DRM.
