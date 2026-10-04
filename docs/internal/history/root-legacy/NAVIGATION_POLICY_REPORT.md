# Arenyxa v8.0 beta17 Navigation Policy Report

## Policy model

Each mode owns a `WorkspacePolicy` with one landing page, no more than eight primary entries, and retained secondary page IDs. The policy engine orders the resolver result without bypassing its Runtime, account role, Developer authority, Root session, or capability decisions.

## Primary navigation

- Personal: Dashboard, Search, Network, Tasks, Data, Settings.
- Professional: Dashboard, Network, Studio, Workflow, Automation, Data, Settings.
- Developer: Developer Center, Protocol, Automation, Workflow, Settings.
- Enterprise: Enterprise Console, Server, Workers, Jobs, Audit, Settings.
- Root Developer: Developer Center, Security Center, Audit, Diagnostics, Version, Settings.

The sidebar marks only these entries as primary. Existing page buttons remain registered and are retained as secondary navigation so beta13 UI/functions are not removed.

## Enterprise and Developer entry rules

`enterprise` is mode-visible without an Enterprise Admin role so Enrollment is reachable. Protected operations inside the console still check real permissions. `developer_center` is mode-visible without Official Developer authority; `console` and `logs` remain credential-gated.
