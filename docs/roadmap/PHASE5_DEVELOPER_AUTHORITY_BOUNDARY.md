# Phase 5 — Private Developer Authority boundary

The Phase-5 Developer Authority is delivered as a physically separate private/offline source archive. It is **not** inside this public source tree, GitHub path or installer.

The private utility implements Root -> Issuing -> Developer certificate trust. Developers generate their Personal Key Pair on their own device and submit only Email + Developer ID + Public Key/fingerprint. The Authority never centralizes Developer private keys and never uses an email whitelist as the trust root.

The Developer Root Private Key is reserved for Issuing-Key administration and offline disaster recovery. Day-to-day Developer certificate issuance uses an Issuing Key. Root, Issuing and backup operations are offline and auditable.

Root Authority integration into the main application remains Phase 6. Phase 5 does not add a Root-private-key login path to Arenyxa. The future Root Developer session may expose all Arenyxa platform engineering functions through an explicit Root Authority mechanism, but it must not implicitly grant customer Enterprise business-data permissions.
