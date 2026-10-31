---
status: current
owner: architecture
last_reviewed: 2026-10-28
---

# Architecture Decision Records

ADRs are append-only decisions. Preserve original decisions; do not rewrite history when implementation or policy changes. A replacement receives the next available numeric ID.

| ADR | Decision | Lifecycle | Summary |
| --- | --- | --- | --- |
| [0001-runtime-boundary.md](0001-runtime-boundary.md) | Run Runtime Boundary | stable / accepted | RunOrchestrator owns Run lifecycle, cancellation, progress, and durable state. |
| [0002-workflow-runtime-boundary.md](0002-workflow-runtime-boundary.md) | Workflow Runtime Boundary | stable / accepted | WorkflowEngine and WorkflowDatasetService own deterministic execution and checkpoint/resume consistency. |
| [0003-dataset-boundary.md](0003-dataset-boundary.md) | Dataset Boundary | stable / accepted | DatasetVersionService and DataLineageService own revision identity, ancestry, and lineage evidence. |
| [0004-capture-boundary.md](0004-capture-boundary.md) | Capture Boundary | stable / accepted | Defines capture ingestion ownership and isolation. |
| [0005-recovery-boundary.md](0005-recovery-boundary.md) | Recovery Boundary | stable / accepted | Defines recovery orchestration and state continuity. |
| [0006-plugin-boundary.md](0006-plugin-boundary.md) | Plugin Boundary | stable / accepted | Defines plugin execution and trust boundaries. |
| [0007-storage-boundary.md](0007-storage-boundary.md) | Storage Boundary | stable / accepted | Defines storage and durable persistence ownership. |
| [0008-ui-shell-boundary.md](0008-ui-shell-boundary.md) | UI Shell Boundary | stable / accepted | Keeps UI shell state separate from application/runtime truth. |
| [0009-reliability-resource-governance.md](0009-reliability-resource-governance.md) | Reliability and Resource Governance | stable / accepted | Records reliability budgets and resource governance. |
| [0010-workflow-test-lab.md](0010-workflow-test-lab.md) | Workflow Test Lab | stable / accepted | Records workflow-test-lab architecture boundaries. |
| [0011-hardware-root-tpm-lifecycle.md](0011-hardware-root-tpm-lifecycle.md) | Hardware Root TPM Lifecycle | stable / accepted | Records TPM hardware-root lifecycle, fail-closed rules, and recovery boundaries. |
| [0012-v7-8-async-io-and-capability-layers.md](0012-v7-8-async-io-and-capability-layers.md) | v7.8 Async I/O and Capability Layers | historical snapshot | Historical v7.8 decision on async I/O, optional capabilities, and legacy compatibility. |

## Supersession policy

Only mark an ADR superseded when an explicit replacement ADR exists. Add `superseded_by: 00NN` to the ADR metadata and index, and link to the replacement. Do not infer supersession from age or version labels.
