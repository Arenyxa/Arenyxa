# Enterprise Operation Convergence

Arenyxa treats Enterprise ownership as a backend security property, never as a presentation/UI property.

## Core invariant

Once a local object is bound to an Enterprise resource, supported local execution paths must not silently fall back to Personal-mode behavior when the Enterprise Vault is locked, the Enterprise session expires, or a different Enterprise is active.

The encrypted Enterprise Vault remains authoritative for RBAC, resource scope, approvals, quota and policy. SQLite stores only a non-secret ownership binding:

- local resource kind;
- local external ID;
- Enterprise governance resource ID;
- Enterprise ID;
- binding timestamps.

This ownership index is intentionally available while the Vault is locked so legacy/local runtimes can fail closed before producing side effects.

## Covered local operation gates

- Task / local Runner execution -> `workflow.execute`
- Direct Workflow execution -> `workflow.execute`
- Governed Workflow publication -> `workflow.publish` + approval
- Dataset-to-Workflow runtime -> `workflow.execute`, source `dataset.read`, output `dataset.write`
- Capture start -> `enterprise.capture.run`
- Schedule callback execution -> `schedule.manage`, followed by the Task workflow gate

Distributed Server submission continues to use `EnterpriseGovernanceService.authorize_operation()` directly and therefore shares the same underlying Governance authority.

## Registration consistency

Production `EnterpriseGovernanceService` is store-aware. Resource registration stages the local ownership binding before mutating encrypted Governance state. If Governance registration fails, the binding is compensated. If compensation itself cannot be persisted, the binding deliberately remains in place so the local resource is blocked rather than becoming accidentally ungoverned.

`EnterpriseOperationGuard.register_and_bind_resource()` provides the same fail-closed behavior for integrations that construct a Governance service without a binding store.

## Observability

Enterprise local-operation gates emit hash-chained Audit events and correlation IDs. JSON application logs preserve common correlation fields such as Run, Workflow execution, Worker, Job, Capture and Enterprise identifiers.

## Operator health

`EnterpriseGovernanceService.operations_snapshot()` exposes:

- `bound_local_resources`
- `orphaned_local_bindings`

An orphaned binding is fail-closed and should be investigated rather than automatically deleted.
