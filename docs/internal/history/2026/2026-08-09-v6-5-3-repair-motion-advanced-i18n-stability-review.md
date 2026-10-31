# Arenyxa V6.5.3 Repair UX, Motion, Advanced Features & i18n Stability Review

Date: 2026-08-09

## Scope

V6.5.3 is a stability and UX-hardening release on top of V6.5.2. It keeps the V6.5 Dataset/Data-Lineage/Workflow persistence contract unchanged and focuses on four cross-cutting failure classes: startup diagnostics appearing before the product surface exists, layout-fighting page transitions, incomplete runtime language switching, and advanced UI surfaces drifting away from their backing application services.

## Startup health and Repair Center

Normal startup no longer runs the health scanner before `MainWindow` is visible. The desktop is created and painted first; the read-mostly health scan then runs on the shared background pool. Findings are surfaced through a dialog parented to the visible Arenyxa window. A bootstrap failure that prevents the full workspace from being created first opens a lightweight Arenyxa Recovery Mode shell and parents repair dialogs to that shell. The only unavoidable pre-UI exception is a missing Qt/PySide6 dependency, because no Qt application surface can exist in that condition.

Repair Center now renders the concrete finding title, category, code, detail and evidence instead of only listing broad categories. A new `FEATURE_INTEGRATION` category covers missing advanced-module wiring and its conservative repair path verifies/restores the advanced implementation files before relaunch. Repair report counts and evidence labels are localized.

## Page-transition motion

Page navigation now commits state through `MotionOrchestrator.transition_stack()`. The outgoing page is captured once as a lightweight snapshot overlay, the target page is laid out underneath, and a short `OutCubic` cross-fade removes the overlay. Layout-managed page geometry is never animated. This avoids the prior competition between Qt layouts and direct widget movement that could cause micro-jumps, especially on complex Studio and Network pages. Rapid route changes cancel and clean up the prior overlay, reduced-motion remains immediate, and efficiency mode falls back to an instant switch.

## Advanced-feature implementation audit

`application.feature_audit` declares an explicit side-effect-free runtime contract for every advanced service exposed by the desktop. The V6.5.3 baseline verifies 30/30 contracts after a real `ApplicationContext` bootstrap. Every `NextGenFeatureHub` field is represented by a contract, and core advanced runtime modules are checked for placeholder-only implementations (`pass` / `NotImplementedError`).

The audit verifies implementation/wiring, not the availability of optional external software. Features such as live Playwright browser recording, tshark/dumpcap capture, remote workers or marketplaces can be fully implemented while reporting an unavailable external runtime/dependency. This distinction prevents false claims and false repair attempts.

## Runtime localization

The language walker now tracks both Chinese-first and catalogued English-first application literals as stable semantic sources. Hot switching can therefore proceed English → French → Japanese → Simplified Chinese without treating the previously rendered translation as new source text. The source catalogue was expanded for advanced Studio actions, specialist descriptions, Repair Center details and remaining static Chinese-first controls.

Editable user content is explicitly outside the translation path. URL fields, JSON/code editors, commands, logs, technical identifiers, Worker IDs and editable plain-text content remain byte-for-byte user/application data. Read-only helper copy, labels, buttons, tabs, combo items, table headers, placeholders and safe bounded metric counters can be localized.

## Stability gates

V6.5.3 adds regression contracts for deferred startup health scanning, visible recovery-shell parenting, snapshot page transitions, advanced runtime wiring, placeholder implementation detection, specialist localization coverage, direct static Chinese UI registration and real Qt hot-switch behavior (executed when PySide6 is available). Repair seed/manifest and source integrity manifests must be regenerated only after code freeze.
