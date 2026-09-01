# Arenyxa v8.2 Merge Matrix

Status: ACTIVE RELEASE-INTEGRATION EVIDENCE

This matrix records the semantic integration state used for the v8.2 release branch. It is intentionally evidence-driven: a historical report is not treated as source truth unless its behavior is present in an available source tree and/or independently revalidated.

## Inputs

| Line | Identity | Evidence state | Role |
|---|---|---|---|
| GPT_REPAIR_A | `Arenyxa_v8.1.1_GPT56Sol_Fixed.zip` lineage, represented by the byte-verified `Arenyxa_v8.1.1_Integrated_Latest_Source.txt` reconstruction | Source-bearing | Repair-integrity baseline |
| GPT_REPAIR_B | Architecture/refactor repair line described in the Sol handoff and independently reproduced into the integrated source tree | No separate final ZIP available in the current environment; reproduced code is source-bearing | Architecture/regression closure |
| REMOTE_RELEASE_LINE | `release/v8.1.1-final` at `257b057966d66069aacd0efc8ef41d3d302b1ba1` | Source-bearing GitHub branch | Later lifecycle/closure work that must not be regressed |
| V82_WORK | `release/v8.2` | Source-bearing GitHub branch | Final semantic integration target |

## Critical repair matrix

| Area | GPT_REPAIR_A | GPT_REPAIR_B / integrated result | REMOTE_RELEASE_LINE | v8.2 disposition | Classification |
|---|---|---|---|---|---|
| Canonical source inventory / release identity | Present | Preserved | Present/modified release files | Preserve strongest verified contract | SAME / MERGED |
| `SOURCE_MANIFEST` binding | Present | Preserved | Present | Preserve and regenerate only after final source closure | SAME |
| Repair attestation / immutable verified seed | Present | Preserved | Present | Preserve; final artifacts must bind to final revision | SAME |
| Stale seed rejection | Present | Preserved | Present | Preserve | SAME |
| Same-version / different-revision rejection | Present | Preserved | Present | Preserve | SAME |
| Repair seed TOCTOU protection | Present | Preserved | Present | Preserve | SAME |
| VERIFY → STAGE → PREPARE/JOURNAL → COMMIT → POST-VERIFY | Present | Preserved | Present | Preserve transactional sequence | SAME |
| Rollback / interrupted transaction recovery | Present | Preserved | Present | Preserve and revalidate on Windows installer | SAME |
| Forbidden historical artifact filtering | Present | Preserved | Present | Preserve | SAME |
| Phase-0 canonical verifier | Present | Preserved | Present | Must PASS after final v8.2 artifact regeneration | SAME |
| Developer navigation authority leakage | Fixed | Preserved | Later lifecycle line touches navigation/bootstrap surfaces | Keep semantic authority fix; regression-test after merge | CONFLICT-RISK / MERGED |
| TPM KeyProtection deterministic error semantics | Fixed | Preserved | No contradictory evidence found | Preserve | SAME |
| `crawler_intelligence` FeatureContract | Fixed | Present (`analyze`, `analyze_browser`) | No contradictory evidence found | Preserve and revalidate | SAME |
| i18n direct Chinese UI phrase coverage | Fixed | Present | Later GUI/bootstrap changes may add strings | Preserve; rescan final tree | CONFLICT-RISK |
| Repair downgrade/version fencing | Present in integrated result | Preserved | Present release identity changes | Preserve strongest fencing semantics | MERGED |
| `RepairPlan` version identity | Present | Preserved | Present | Preserve | SAME / MERGED |
| External Repair Worker version validation | Present | Preserved | Later lifecycle shutdown work exists | Merge both identity and shutdown semantics | CONFLICT-RISK / MERGED |
| `distributed_queue_leases.py` split | N/A | Present | Queue architecture further evolved | Preserve behavioral split where compatible | MERGED |
| `distributed_queue_maintenance.py` | Absent from integrated reconstruction | Absent | Present | Preserve remote lifecycle/maintenance module | ONLY_REMOTE |
| `runtime_storage_postgresql.py` split | N/A | Present | PostgreSQL architecture evolved further | Semantic compare required before PG optimization | CONFLICT-RISK |
| `runtime_storage_sql.py` | Absent from integrated reconstruction | Absent | Present | Preserve remote SQL split | ONLY_REMOTE |
| `bootstrap_context.py` split | N/A | Present | Bootstrap architecture further evolved | Preserve compatible context split | MERGED |
| `bootstrap_services.py` | Absent from integrated reconstruction | Absent | Present; initially had missing `RunHandle` dependency | Preserve remote module; fixed explicit dependency in v8.2 | ONLY_REMOTE / FIXED |
| `exception_boundary.py` | Absent from integrated reconstruction | Absent | Present | Preserve typed boundary helper; use where semantically correct | ONLY_REMOTE |
| Capture proxy size regression | Fixed | Present | Later line may alter capture lifecycle | Revalidate final architecture gate | CONFLICT-RISK |
| Broad `Exception` debt ratchet | Historical integrated tree: 298 > 284 | Still a known blocker there | Actual remote target pending post-F821 gate | Do not raise budget; refactor confirmed excess only | OPEN |
| Long-function ratchet | Closed | Closed | Later splits reduce large modules | Preserve; no budget increase | SAME / IMPROVED |
| SQLite compatibility migration fixtures | Present | Preserved | Later lifecycle line includes migration tests | Preserve | SAME / MERGED |
| Release identity / compatibility matrix | Present | Preserved | Release-line changes present | Rebuild deliberately for v8.2; do not mechanically replace historical compatibility values | CONFLICT-RISK |

## Confirmed remote-only lifecycle modules that must not be overwritten

- `src/arenyxa/bootstrap_services.py`
- `src/arenyxa/enterprise/distributed_queue_maintenance.py`
- `src/arenyxa/enterprise/runtime_storage_sql.py`
- `src/arenyxa/exception_boundary.py`

## v8.2 merge rule

No whole-file overlay from either historical GPT repair snapshot is permitted where the remote release line has later source-bearing work. Critical paths are merged by invariant and behavior, followed by deterministic regression and CI evidence.

## Current merge verification checkpoint

- `release/v8.2` was forked from remote `release/v8.1.1-final`, preserving its 45-file closure delta over `main`.
- Historical integrated source reconstruction: 1171 text files reconstructed and verified against embedded size/SHA-256 metadata.
- The remote release line exposed one deterministic static integration defect: `bootstrap_services.py` referenced `RunHandle` without importing it.
- v8.2 production fix: explicit import from `arenyxa.application.runner_support`; Ruff F821 check was run in the one-shot repair workflow before commit.
- No architecture/security/performance threshold was weakened.

This file will be finalized again at release closure with final commit identities and resolved OPEN rows.
