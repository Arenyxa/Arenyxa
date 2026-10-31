# Arenyxa — Binding Constraints Carried Into the Roadmap

Date: 2026-08-12

These constraints are intentionally recorded during Phase 0 so later phases cannot accidentally reinterpret them while changing authentication, enterprise, developer, or distributed-runtime code.

## Development sequencing

- Advance one Roadmap Phase at a time. A later Phase does not start merely because its code is easy to add.
- Each Phase must preserve a rollback path and pass its own targeted tests, historical regression, integrity checks, fresh-extract verification, and the native checks relevant to that Phase.
- Stability, reliability, compatibility, failure semantics, and denial paths outrank feature count.
- Git history/tagging and Inno Setup packaging are outside source-code delivery unless explicitly requested by the owner.

## Root Developer / Developer Trust

- Root Developer is the highest **Arenyxa platform engineering authority** in an official build. Later implementation should model this as an explicit Root Authority mechanism rather than scattered special-case bypasses.
- Root Developer authority may unlock Arenyxa platform engineering capabilities, internal diagnostics, test/fault tooling, release verification, and Developer Trust administration.
- Root Developer authority must **not** become a universal key for customer Enterprise business data. Enterprise resource access remains subject to the customer's Enterprise authorization boundary unless the customer explicitly grants scoped, time-bounded, auditable support access.
- Developer Trust and Enterprise Trust are separate trust domains. Developer Root, Release Signing Root, and every Enterprise Root remain separate key hierarchies.

## Developer key handling

- The private Arenyxa Developer Authority Utility remains local, private, offline, and owner-controlled; it is not part of the public repository or installer.
- Developer Root Private Key never enters the public Arenyxa source tree, main program, installer, or chat-based transfer workflow.
- Root signs/rotates an Issuing Key; ordinary developer certificate issuance uses the Issuing Key rather than routinely exposing the Root Key.
- Each trusted developer generates their own Developer Key Pair locally. Only identity/application metadata and the public key are submitted for signing.
- Developer private keys are never centrally collected by the Root Owner.

## Enterprise / distributed-runtime boundary

- Security primitives precede account/UI products; UI visibility is never authorization enforcement.
- Local single-node Enterprise semantics must be correct before LAN Coordinator or distributed Server/Worker expansion.
- Desktop, Server, and Worker must share the same Core Runtime/state model; do not fork a second runtime for distributed deployment.

## Startup motion visual freeze

- The v6.8 Phase 0 X-style integrated startup animation is a user-approved visual baseline.
- Later phases must not redesign its timing, visual language, icon-to-window handoff, fade behavior, or perceived continuity unless the owner explicitly reopens that scope.
- Multi-monitor, DPI, accessibility, crash, and compatibility fixes remain allowed, but they must preserve the approved visual behavior rather than substitute a new animation.

## Settings / Personalization information architecture

- `Settings` and `Personalization` are separate first-class destinations.
- `Settings` must prioritize operational/product configuration such as language, performance/resource governance, storage/network/security, diagnostics, updates, logs and future enterprise administration.
- Theme presets, appearance, glass/material tuning, motion preferences, contrast and interface scale belong to `Personalization` and must not dominate the Settings landing page.
- Future Enterprise UI must preserve this separation so administrators can reach governance controls without scanning through large visual preset cards.
