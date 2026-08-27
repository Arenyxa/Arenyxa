# Independent Security Review Checklist

## Trust roots
- Verify Release Signing, Developer Identity, and every Enterprise Root remain separate.
- Verify no Developer/Root Owner technical capability becomes an implicit Enterprise data permission.
- Verify production private keys are absent from public source/install artifacts.

## Developer Authority
- Re-review Root/Issuing/Owner/Developer chain validation, revocation, backup/restore and offline operator ceremony.

## Enterprise Vault / IAM
- Re-review AEAD/KDF bounds, atomicity, last-Super-Admin invariants, session generation invalidation, backup/restore rollback and audit fail-closed behavior.

## Coordinator / Server protocol
- Verify TLS identity binding, Enterprise Root signature, one-shot challenges, replay resistance, protocol downgrade rejection, request bounds and rate/admission controls.
- Verify worker lease loss never automatically repeats a non-idempotent side effect after its side-effect fence is marked started.
- Verify worker drain/revoke, server restart, network partition and duplicate delivery have deterministic recovery semantics.

## Release / migration
- Corrupt each backup/control artifact and prove migration refuses it.
- Inject failure after every migration step and prove byte-exact control-file rollback plus SQLite verified-backup restore.
- Run N/N-1 compatibility and old-client/new-server protocol tests.

## Native Windows / multi-machine
- Real Windows multi-monitor + 100/125/150/200% DPI.
- Service install/start/stop/restart, sleep/resume, network switch, firewall, storage disconnect.
- Two-machine Worker loss and partition tests; LAN MITM/replay tests.
- Upgrade, rollback and uninstall on clean and upgraded hosts.
