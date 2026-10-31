# Arenyxa V6.5 — Workflow Engine Integration

Date: 2026-08-09  
Status: release candidate implementation

## Scope

V6.5 closes the first durable data-processing loop:

`Run -> Dataset Revision -> Workflow -> Dataset Revision -> Lineage`

It reuses the existing Workflow Engine and adds persistence, checkpoints, Dataset I/O, node metrics, cancellation/resume, and provenance around that engine.

## Durable execution model

Each execution has a persistent `workflow_executions` row. The row records source/output revision IDs, semantic workflow-definition hash, state, progress counters, last committed input identity, bounded checkpoint JSON, and bounded error details. Per-node counters are stored in `workflow_node_executions`.

The output revision is created in `building` state and stays hidden from normal Dataset history until successful finalization.

## Streaming and bounded memory

The runtime reads the source revision through keyset pagination and processes one immutable source record at a time. Output records are staged in bounded batches. Large Dataset workflows therefore do not require loading the full source or full output into RAM.

## Deterministic output identity

Each emitted output identity is derived from source-record identity, workflow ID, and output ordinal. If a process is interrupted after staging output but before checkpointing its source input, resume may execute that input again, but the same staged output identities are replaced rather than duplicated. This provides practical idempotence across the checkpoint boundary.

## Cancellation and resume

Cancellation is cooperative. The runtime flushes completed output, checkpoints only fully completed input records, marks the output revision `cancelled`, and marks the execution `cancelled`. `resume_execution()` can continue cancelled/interrupted executions from the durable keyset checkpoint.

Resume verifies a semantic definition hash. Workflow provenance timestamps are intentionally excluded; executable identity/version/schema/nodes are included. If executable semantics changed, resume fails with `WORKFLOW_RESUME_DEFINITION_CHANGED` rather than combining outputs from different definitions.

## Failure handling

Unexpected execution failures mark both the Workflow execution and its output revision failed. Partial revisions are retained for diagnostics but not published. Successful runs finalize the revision and switch the Dataset's current revision atomically. Executions discovered active after an unclean shutdown become `interrupted` during bootstrap recovery.

## Node metrics

Node execution counts, emitted counts, dropped counts, failure counts, and accumulated duration are persisted. This provides a durable foundation for later profiler, optimization, and Autopilot outcome feedback without requiring raw payload logging.

## End-to-end lineage

V6.5 adds provenance edges for:

- source Dataset Revision -> Workflow Execution: `input_to`
- Workflow -> Workflow Execution: `executed_as`
- Workflow Execution -> output Revision: `produced`
- parent Revision -> output Revision: `parent_of`
- output Revision -> Dataset: `version_of`

## Release gate

The release must pass:

1. fresh migration through schema version 10;
2. Dataset-to-Workflow-to-Dataset integration;
3. cancellation followed by resume without duplicate output;
4. workflow-definition mismatch rejection;
5. legacy test regression;
6. source repair-seed integrity regeneration;
7. source manifest regeneration and verification;
8. compile and packaged-source re-extraction checks.

## Next engineering step

The next safe expansion is not to let Autopilot mutate workflows autonomously. First expose V6.5 execution outcomes as bounded, privacy-preserving feedback features to the existing advisory learning layer, then require explicit policy/permission gates before any adaptive execution strategy can alter a Workflow.
