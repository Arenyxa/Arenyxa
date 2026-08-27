# ADR 0010 — Workflow Test Lab is isolated from production execution state

**Status:** Accepted for Phase 3  
**Date:** 2026-08-12

## Decision

Workflow dry-run, fixtures, mock HTTP and Golden Output regression execute on a fresh in-memory Workflow Engine. Test mocks never register on the production engine and real network access is not a fallback for missing mocks.

## Consequences

- Regression is deterministic and reproducible.
- Tests cannot accidentally issue a real HTTP side effect because a fixture forgot a mock.
- Golden output is canonicalized and hashed for compact evidence.
- Dataset lineage/checkpoint persistence remains owned by the production Workflow Runtime, not the Test Lab.
