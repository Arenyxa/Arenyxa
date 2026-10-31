---
status: current
owner: release
last_reviewed: 2026-10-28
---

# Machine-readable metadata

- [release-identity.json](release-identity.json) is the canonical public release identity. Product, package, Windows, engineering-baseline and compatibility identities are intentionally separate.
- [manifests/](manifests/) contains retained machine-readable gate results and pinned performance baselines. These are evidence, not a substitute for the current human release decision in [docs/RELEASE_STATUS.md](../docs/RELEASE_STATUS.md).
- [schemas/](schemas/) defines machine-readable metadata contracts.
- Older identity, test-run, chaos, and performance records are preserved under [docs/internal/history/](../docs/internal/history/).
- Root requirements TXT files remain in place because packaging and environment setup consume them as dependency inputs; they are not narrative documentation.
