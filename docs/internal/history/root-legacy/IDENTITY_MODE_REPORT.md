# Arenyxa v8.0 beta17 Identity and Mode Report

## Mode versus authority

Experience Mode selects the workspace. Authority continues to decide operations. Selecting Developer or Enterprise never mints a credential, role, capability, or Root session.

## Mode flows

- Personal persists the selected first-run scenario and restores its landing page after restart.
- Professional preserves the complete analysis/automation workspace.
- Developer immediately persists the mode, updates `ExperienceContext`, emits `ModeChangedEvent`, rebuilds navigation, refreshes the sidebar, and opens the existing Developer Center.
- Enterprise immediately opens the existing Enterprise Console. With no identity configured, the console shows Enterprise Enrollment with real “create local enterprise” and “join enterprise” actions.
- Root Developer is enabled only by an active per-process Root challenge session. A stored `root_developer` preference without an active Root session falls back to ordinary Developer mode.

## Security boundary

Developer Center can be entered without Official Developer authority, while Terminal Console and other protected tools keep their original capability checks. Enterprise Console can be entered without an enterprise account, while account, Fleet, Worker, Job, Audit, Vault, Coordinator, and Policy operations remain controlled by existing role/capability checks.
