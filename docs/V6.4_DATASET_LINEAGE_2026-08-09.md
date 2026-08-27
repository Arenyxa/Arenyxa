# Arenyxa V6.4 — Dataset / Data Lineage

Date: 2026-08-09  
Status: integrated into the V6.5 source baseline

## Scope

V6.4 establishes Dataset as the stable bridge between collection Runs and downstream analytical/workflow features. The design deliberately keeps Dataset publication separate from construction: consumers only see revisions that reached `ready`.

## Persistence and migration

SQLite migration 9 adds the Dataset registry, revision build state, and deterministic lineage node/edge tables. Existing revision rows are treated as `ready`, preserving prior data semantics. Migration remains transactional and is covered by the existing migration backup/rollback path.

## Revision lifecycle

A new revision begins in `building`. Records are appended in bounded batches using short transactions. Successful completion atomically marks the revision `ready` and updates `datasets.current_revision_id`. Cancellation, process recovery, or execution failure produces `cancelled`, `interrupted`, or `failed`; these revisions are excluded from ordinary revision listings unless diagnostic code explicitly requests incomplete revisions.

## Run materialization

`DataLineageService.materialize_from_runs()` consumes canonical ResultRecords through keyset/streaming database reads rather than collecting all source data in memory. Active Runs are rejected. The service applies a hard record budget, bounded batch writes, cancellation checks, and deterministic last-source-wins behavior when several selected Runs contain the same logical record identity.

## Record identity and schema

When callers specify identity fields, canonical JSON of those logical keys is SHA-256 hashed into a stable record identity. Otherwise a canonical content hash is used. Schema inference is performed online and stores bounded structural type information. Integer and number observations widen to number; incompatible observations become mixed.

## Data lineage

The persistent graph records the minimum provenance required to answer where a dataset came from and what it produced:

- Task -> Run: `executed_as`
- Run -> Dataset Revision: `materialized_into`
- Parent Revision -> Revision: `parent_of`
- Dataset Revision -> Dataset: `version_of`

Traversal is bounded by depth and node count and guards against cycles.

## Stability and recovery

Legacy Run/Capture recovery retains its exact return contract. Dataset/Workflow recovery is a separate pipeline recovery operation. On startup, abandoned `building` revisions become `interrupted`, preventing accidental publication while preserving staged data for diagnosis or a higher-level resume operation.

## Privacy boundary

Lineage stores bounded structural metadata. It does not duplicate raw response bodies, request bodies, Authorization/Cookie values, tokens, or arbitrary captured headers. The Dataset record itself remains governed by normal project/storage access controls.

## Release gate

Required verification includes fresh-database migration, Run-to-Dataset materialization, duplicate logical identity behavior, failed/incomplete revision visibility, lineage traversal bounds, compile validation, and regression testing of pre-V6.4 Run/Capture recovery.
