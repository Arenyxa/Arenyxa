# Arenyxa V6.5.4 Self-Healing & Runtime Recovery Hardening

## Scope

V6.5.4 remains inside the V6.5 product line. It does not change the Dataset/Data-Lineage/Workflow persistence contract introduced by V6.4/V6.5. Instead it hardens the recovery boundary around persisted execution state and makes Repair Center diagnostics more precise and auditable.

## Fault fingerprints

Every `RepairFinding` now receives a deterministic `NXF-xxxxxxxxxxxx` fingerprint derived only from the stable diagnostic category and code. Runtime evidence is deliberately excluded because evidence can contain local paths, object identifiers or URLs. The fingerprint therefore identifies a repair rule without leaking user data and remains stable across machines and sessions.

Repair Center displays the fingerprint next to the category/code and serializes it into the health report. This gives diagnostics and bug reports a compact identity that survives localization and wording changes.

## Runtime recovery service

`application.runtime_recovery.RuntimeRecoveryService` owns persisted lifecycle recovery across Run, Capture, Workflow Execution, Dataset Revision and Scheduler state.

On single-instance startup it:

- closes orphaned `queued/running/paused` Runs as interrupted failures while preserving ResultRecords;
- closes active Capture sessions while preserving NetworkEvents and recomputing event/byte counters;
- converts active Workflow executions to `interrupted` so durable checkpoints can be resumed;
- converts Dataset revisions left in `building` to `interrupted`;
- disables malformed persisted schedules without deleting their rule JSON;
- normalizes invalid Workflow/Revision lifecycle values to `failed`;
- validates interrupted Workflow resume chains and refuses unsafe resume when the workflow definition, ready source revision, or incomplete output revision is missing;
- preserves staged output Revision records even when a broken resume chain must be failed.

A bounded `repair/runtime_recovery_history.json` stores structural recovery evidence and counts. It never copies record bodies, request headers, cookies or secrets.

## Targeted Repair Center behavior

Program-file restoration is no longer implied merely by a startup crash or language issue. Editable source trees must not be replaced without actual `PROGRAM_FILES` evidence or an explicit general repair request. Plugin quarantine and cache clearing are likewise no longer generic crash side effects; they run when the corresponding category is detected or explicitly selected.

This reduces repair blast radius while preserving the conservative `OTHER` fallback.

## Proactive diagnostics

Startup health scanning now performs side-effect-free checks for:

- stale runtime ownership state;
- malformed enabled schedules;
- invalid Dataset Revision lifecycle/recovery metadata;
- invalid Workflow Execution lifecycle/resume chains;
- malformed plugin manifests or unsafe plugin entry paths.

Invalid plugins are only reported during scanning. Repair Center later moves them into timestamped quarantine and preserves prior quarantine evidence.

## Safety contract

V6.5.4 repair remains non-destructive toward user data:

- Projects, Captures, Exports and formal results are never bulk-deleted;
- staged Workflow output records are preserved for diagnostics;
- invalid schedules are disabled, not deleted;
- invalid plugins are quarantined, not erased;
- repair history stores structural metadata only;
- unknown port owners and unrelated processes are never killed.
