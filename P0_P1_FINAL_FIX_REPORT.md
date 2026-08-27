# Arenyxa v7.8 P0/P1 Closure Report

This source tree contains the v7.8 P0/P1 reliability hardening pass.

## P0 closure

- Async/sync boundary: SQLite/result persistence and progress callbacks used by `AsyncRunOrchestrator` are offloaded from the asyncio event-loop thread; cancellation/finalization paths explicitly drain pending request tasks.
- Distributed lease state machine: PostgreSQL lease transitions use row-level locking, expired-lease recovery uses conditional stale-state checks, renew expiry is calculated after lease validation, and queue invariants can be audited explicitly.
- External runtime contracts: tshark/dumpcap/mitmdump now have bounded version/capability probes. Required tshark fields are validated before execution, and incompatible/missing capabilities fail explicitly instead of silently projecting empty values.

## P1 closure

- Broad exception governance: source ceiling reduced to 261; critical execution/capture files require explicit `broad-exception-boundary:` classification for every deliberate `except Exception` boundary.
- Coverage governance: global coverage floor raised from 35% to 40%; CI now enforces a dedicated critical-module gate over async orchestration, distributed leases, TCP reassembly, external-tool contracts, and headless developer access.
- Developer CI access: headless login reuses the signed Developer bundle/challenge flow and encrypted credential vault. Passphrases are callback/stdin supplied; no root passphrase environment-variable bypass was introduced.

## Validation performed in the build environment

- Python compileall: PASS.
- Focused P0/P1 + architecture + async + distributed + protocol + MITM regression set: 67 passed.
- Critical coverage regression set: 54 passed; aggregate measured coverage 58.6% across the five guarded modules; gate PASS.
- Architecture debt gate: PASS (`broad_exception=261`, `enterprise=38`, `proxy=1`).
- Exception quality gate: PASS.

`static_quality_gate.py` additionally requires the development dependency `ruff`, which was not installed in the build environment, so that external-tool-dependent gate was not represented as executed here.
