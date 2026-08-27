# Arenyxa v7.0 GitHub Publication Audit — 2026-08-14

## Decision

**Public-source publication gate: PASS**, subject to the release caveats below. This audit is for the public GitHub source tree; it does not declare an installer cryptographically "official" and does not replace native Windows/distributed deployment drills.

## Fixes folded into the publication tree

- Integrated the Windows PluginSandbox venv/Job Object worker-launch fix instead of shipping a transient patch as part of the repository.
- Corrected the Phase-4 UTC-naive test clock to use `datetime.now(UTC).replace(tzinfo=None)` so local Windows timezone does not create a false session-expiry failure.
- Corrected Pascal Script comments in both `packaging/installer.iss` and `packaging/installer_win7.iss` `[Code]` sections from `;` to `//`.
- Added a v7.0 regression contract that rejects semicolon comments in Inno `[Code]` sections.
- Hardened `.gitignore` against local virtual environments, build output, editor state, release-signing keys, Developer/Owner/Enterprise private vaults and login artifacts, private Authority archives, transient patch scripts, and generated quality reports.
- Added `.gitattributes` with deterministic LF text checkouts so Git on Windows cannot invalidate `SOURCE_MANIFEST.sha256` merely through CRLF conversion.
- Added `scripts/github_publication_gate.py` as a fail-closed public-source scan.

## Public/private boundary

The public repository may contain public release trust anchors, embedded public Developer Root trust artifacts, public revocation snapshots, schemas, verification code, and build/verification tooling. It must not contain any Developer Root private vault, Issuing private vault, Owner/Developer device private vault, Enterprise identity vault, release-signing private key, Worker private key, private Developer Authority source package, passphrase, bearer token, personal login bundle, or personal environment file.

The private `Arenyxa Developer Authority Utility` remains a separate offline asset and is intentionally outside the public repository and installer.

## Automated publication checks

`python scripts/github_publication_gate.py` passed on the cleaned final tree:

- required public repository documents present: `README.md`, `LICENSE`, `NOTICE.md`, `SECURITY.md`, `TRADEMARKS.md`, `.gitattributes`, `.gitignore`, `pyproject.toml`;
- no private key/vault/Authority artifacts detected;
- no common credential-token signatures detected;
- no user-specific Jerry profile path, Arenyxa development path, or Root Owner email detected;
- no forbidden assistant/provider branding detected;
- no case-insensitive path collisions detected;
- all relative Markdown links resolve;
- largest repository file is the required self-healing `repair_seed.zip`, about 1.8 MiB, far below GitHub's normal per-file limit;
- nested repair-seed content was separately extracted and scanned: no private key/vault/credential artifact detected.

## Code/release gates re-run

- Arenyxa v7.0 release identity: PASS (`7.0` display / `7.0.0` package / `6.8.0` compatibility identity).
- Python 3.8 grammar gate: PASS, 120 files.
- Phase 1–12 static security scan: PASS.
- startup visual frozen hashes: PASS / unchanged.
- Welcome Center top-level-window contract: PASS.
- UI button wiring contract: PASS, 138 page buttons wired.
- Phase-12 config parse gate: PASS.
- focused source-manifest/version/PluginSandbox/Phase-4 regression: PASS.
- full regression was executed in four bounded groups on the final code line: 152 passed (+ one Qt module collection skip), 203 passed, 144 passed / 4 skipped, and 97 passed / 7 skipped. The pass total is 596; the skipped coverage is environment/native-Qt/Windows-process/DPI related, including two modules skipped at collection because no supported Qt binding is installed in the audit container.

## GitHub publication notes

Historical 6.x/Arenyxa migration documents are intentionally retained as project history and compatibility evidence. `src/arenyxa` is also intentionally retained as the internal compatibility namespace; the active public product identity remains Arenyxa v7.0.

For a public repository, enable GitHub's secret scanning/push-protection controls in addition to the local publication gate. The local gate is defense in depth and is not a substitute for GitHub's server-side scanning.

## Remaining release caveats

The GitHub source tree is publication-ready, but a public source push and an "official signed installer" are different release events. `src/arenyxa/release_keys.py` currently contains no official release public key, so an unsigned build remains an unverified/community distribution. Root Developer public trust is also intentionally empty until the controlled Root ceremony is completed and only the validated public Root trust artifact is embedded.

Native Windows installer/runtime checks and real Server + multiple Worker fault drills remain separate release evidence requirements.
