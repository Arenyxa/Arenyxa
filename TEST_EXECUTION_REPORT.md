# Arenyxa v8.0 Test Execution Report

## Decision

Local engineering regression for the v8.0 source promotion passed. External/native production certification remains incomplete where this execution host lacks required Windows, PostgreSQL multi-node, TShark and static-analysis tool prerequisites.

## Executed on this host

- Python compileall: PASS.
- Stable release identity gate: PASS (`8.0` / `8.0.0` / `8.0.0.0`, compatibility identity retained at `6.8.0`).
- Python 3.8 legacy grammar: PASS, 140 files.
- Full pytest regression: PASS using deterministic shards because the host command runner imposes a per-command wall-time limit. All 149 test files were executed: **1,256 passed, 19 skipped, 0 failed**.
- Post-promotion impacted regression: **33 passed, 0 failed**.
- Phase 6 survivability/performance gate: **106 passed, 0 failed**; bounded telemetry/proxy/SQLite/resource-pressure microbaseline PASS.
- Phase 0 integrity: PASS.
- GitHub/publication safety gate: PASS.
- Architecture debt gate: PASS.
- Exception quality gate: PASS.
- Production configuration gate: PASS.
- Performance regression gate: PASS.
- PDF v8 acceptance gate: all local engineering gate booleans PASS; production certification status remains PARTIAL because external validations below were not executable.

## NOT EXECUTED / environment-bound

- `test-all.ps1`: PowerShell is not installed on this Linux host. Its Python-backed compile/test/integrity semantics were executed directly where available.
- Ruff + Mypy static gate: tools are not installed. An installation attempt was made, but the host has no working DNS/network path to the package index.
- Windows native qualification: no Windows host/VM, QEMU, `/dev/kvm`, Wine or PowerShell environment is available. Therefore Npcap, ETW, WFP, DPAPI, TPM/CNG, Event Log, SCM/Windows Service and native GUI packaging are NOT EXECUTED.
- PostgreSQL 32-worker multi-node gate: no live PostgreSQL DSN/lab supplied.
- TShark differential protocol gate: `tshark` is not installed.

No unavailable item is reported as PASS.
