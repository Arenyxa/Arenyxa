# Arenyxa LTS Policy — Phase 12

- Release channels are **Stable**, **Beta**, **Developer**, and **Enterprise**. A channel changes promotion/testing policy; it does not change Enterprise or Developer authorization.
- LTS feature/maintenance window: 24 months from LTS designation. Security fixes: 30 months.
- Public API/schema deprecation window: at least 12 months unless an actively exploitable security defect requires faster retirement.
- RC/LTS branches are feature-frozen. Large features must return to the next incremental phase instead of entering the release candidate.
- Enterprise Server protocol supports the current protocol and the immediately previous compatible protocol (N/N-1) and negotiates the highest common version.
- Migration is never implicit without preflight and a verified rollback artifact. A migration that cannot be rolled back is a release No-Go.
- Enterprise promotion requires native Windows validation; headless/container test success alone cannot certify Windows Service, DPAPI/TPM/CNG, DPI, sleep/resume, storage disconnect, upgrade/uninstall, or multi-machine LAN behavior.
