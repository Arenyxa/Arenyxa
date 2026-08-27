# Phase 11–12 implementation boundary

Phase 11 introduces a durable SQLite-backed distributed queue, cryptographic Worker identity/challenge sessions, leases/checkpoints/idempotency, non-idempotent side-effect fencing, worker drain/revoke/health, a TLS-only Worker API, the same `RunOrchestrator` on Worker nodes, Server identity bound to an Enterprise Root and TLS certificate, and a verified encrypted-Vault central-authority migration bundle. It does **not** fork a second execution engine.

Phase 12 introduces explicit schema migration policy/registry, preflight, control-file and SQLite backup, verified rollback, channel separation, LTS/deprecation policy, N/N-1 protocol compatibility, machine-readable compatibility matrix, and an independent security audit checklist.

Native Windows Service registration, real multi-machine network partition/MITM tests, Windows upgrade/uninstall and production Root ceremonies remain external release gates; automated source tests cannot certify them.

Operator entry points: `scripts/enterprise_server.py`, `scripts/enterprise_worker.py`, `scripts/enterprise_migration.py`, and `scripts/upgrade_manager.py`. Secrets/passphrases are prompted interactively; no migration/Vault password option is accepted on the command line.

## Root Developer workstation / Platform Root Authority hardening

A Root Developer workstation is not detected by a mutable preference, a hard-coded machine name, or an email whitelist. The Root Owner first completes the normal Owner Authority certificate + owner-device Ed25519 challenge. Arenyxa then stores only the already-validated public Owner login bundle in a Windows DPAPI CurrentUser-protected workstation binding. On future launches the binding is decrypted, revalidated against the build-pinned Developer Root/revocation state/certificate validity, and must still match the exact Owner/Root/certificate/public-key fingerprints.

A validated Root workstation preserves `AppSettings` across launches. Root authority and UX state are deliberately orthogonal: the first verified Root launch keeps a one-time local recovery snapshot, while the active theme, Experience profile, Welcome completion state and other durable preferences remain intact across restarts. Root authorization is re-established from the DPAPI-protected workstation binding and receives a fresh short-lived session after each process start; no Root private key is persisted in the application data root.

Root Owner / Root workstation sessions carry the runtime-only `platform.root` capability. `SecurityKernel` treats this as an explicit platform authority for Personal and Developer technical capabilities, rather than scattered UI special cases. Ordinary Official Developer certificates cannot encode `platform.root`. Enterprise capabilities remain a separate trust domain: Platform Root cannot silently acquire customer `dataset.read`, `enterprise.account.manage`, or enterprise policy authority.

## Enterprise administration layout hardening

The Enterprise page is backed by a vertical `QScrollArea`, and action groups use `ResponsiveActionBar` rather than fixed horizontal button rows. The action bar reflows into a bounded grid, invalidates its layout geometry after a column change, and preserves the original button objects/signals. This prevents SectionCard/action-row collision and clipped controls at small window sizes and high DPI. A static regression test also verifies that every declared Enterprise `QPushButton` has a connected click handler.

Phase 11 adds a read-only/management **Enterprise Server / Distributed Worker** card to the Desktop administration surface. It exposes queue health, bounded Worker views, and bounded Job views through `EnterpriseServerRuntime.remote_ops_snapshot()`. The UI is not an authority boundary; every call is reauthorized by the backend. Starting the actual Server/Worker runtime remains an independent launcher/service operation so the Desktop does not fork a second runtime.

## Distributed transport and hot-path hardening

The distributed queue now rejects duplicate-key persisted JSON, configures/verifies SQLite WAL during initialization instead of repeating `PRAGMA journal_mode=WAL` on every hot-path connection, and short-caches the expensive SQLite integrity probe while keeping job/worker counts live. Worker session timestamps are generated from one instant so returned and stored expiry cannot drift.

The Worker launcher now treats network availability separately from trust/protocol failure. Server restart, expired Worker session, connection reset and temporary network partition trigger bounded exponential reconnect/re-authentication (1–30 seconds); TLS/Enterprise identity failures, revocation, malformed protocol state and execution-integrity failures remain fail-closed. The Worker does not blindly replay a locally-held lease after a transport failure: durable Server lease expiry/checkpoint/idempotency rules decide requeue, and a started non-idempotent side effect is fenced into `review_required`.

Enterprise Server identity timestamp parsing is bounded and domain-error based, with timezone/future-skew/validity checks. Worker HTTP requests require bounded `Content-Length`, reject chunked transfer on sensitive endpoints, reject duplicate-key JSON, and bound integer inputs. Most importantly, the Worker client revalidates the Enterprise-Root-signed Server identity against the **TLS certificate on each sensitive POST connection before transmitting a worker/session secret**, preventing an identity-check/connection-swap gap.

Migration bundles have bounded manifest/member/aggregate uncompressed sizes and reject unsafe reads. Phase-12 backup manifests reject duplicate JSON keys, bind the backup to the exact source data-root identity, and reject migration targets outside the active data root or through symlinks. These checks strengthen rollback/migration semantics without changing the shared Core Runtime architecture.
