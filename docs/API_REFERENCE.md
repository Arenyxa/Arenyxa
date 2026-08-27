# Arenyxa Stable Local API Reference

This document defines the small, stable application-facing surface that release tooling checks. Internal implementation modules may evolve without becoming compatibility promises.

## Command control plane

- `arenyxa.application.command_runtime.ArenyxaCommandRuntime` — shared GUI/headless command runtime with bounded pipelines and professional command groups.

## Persistence

- `arenyxa.infrastructure.database.SQLiteStore` — local durable SQLite/WAL store. SQLite remains the single-host backend; multi-host enterprise deployments use the PostgreSQL runtime-storage path.

## Enterprise runtime

- `arenyxa.enterprise.distributed` — distributed protocol, durable queue, server runtime, and worker runtime facade.
- `arenyxa.enterprise.identity.LocalEnterpriseIdentityService` — local enterprise identity authority facade.

## Terminal

- `arenyxa.application.terminal.TerminalSession` — bounded process/session lifecycle used by the Developer Terminal and headless CLI.
- `TerminalMode`, `TerminalLaunch`, `TerminalResult` — terminal execution contracts.

## Extraction and workflow

- `arenyxa.application.extraction_recipe` — bounded recipe models and compiler for the local browser extraction runtime.
- `arenyxa.application.workflow_graph.WorkflowGraphModel` — original Arenyxa DAG editor/model used by the Visual Graph.

## SQL safety

- `arenyxa.security.sql_safety` — strict identifiers, placeholder generation, and validated SQLite pragma helpers. Dynamic values remain DB-API parameters; identifiers must pass strict validation/allow-lists.

The API contract gate checks that these stable modules and their public top-level symbols remain documented. New internals are not automatically promoted to public API.
