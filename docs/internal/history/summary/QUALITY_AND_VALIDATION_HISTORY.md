# Arenyxa Quality and Validation History

This document consolidates historical acceptance, test execution, quality-gate, security-fix, packaging-fix, and Windows hotfix notes that were previously stored as many separate files.

> Historical record: each section preserves the original filename and text. Current CI status and release certification must be read from the current workflows, release metadata, and active validation policies rather than inferred from an older section below.


---

## Source: `FINAL_ACCEPTANCE_REPORT.md`

# Arenyxa v8.0 Industrialization Delivery

Status: **engineering implementation completed in the current source tree; release certification is environment-gated, not falsely asserted.**

## Source Changes

This delivery applies the v8.0 industrialization work across startup, workflow runtime, storage, lease safety, observability, audit/logging fail-safe behavior, worker partition handling, Windows runtime diagnostics, hot-path memory handling, future callback lifecycle, SQL identifier hardening, repair modularization, reproducible build wiring, quality gate parallelization, dependency security wiring, and release documentation.

Change summary against the supplied source package:

- Added files: 49
- Removed files: 1
- Changed files: 119
- Python production AST `pass`: 0
- Production `TODO`, `FIXME`, `NotImplementedError`, `Dummy Handler`, `Mock Logic`, `Fake Implementation`: 0 findings

## Root Cause Analysis Summary

| Area | Root cause | Fix |
|---|---|---|
| launch.ps1 probe | PowerShell 5.1 merges stderr into structured error records; arrays and RemoteException can turn benign warnings into false probe failure. | Use `System.Diagnostics.Process` in `scripts/launch_probe.ps1`; capture stdout/stderr/ExitCode independently; source startup uses `python.exe -m arenyxa`, not `pythonw.exe`. |
| Browser workflow | Browser Recorder emitted `browser_action`, but runtime contract did not guarantee executable node support. | Added `src/arenyxa/application/browser_workflow.py`, runtime execution, validator contract, and `scripts/workflow_contract_gate.py`. |
| Workflow drift | Producers, serializers, migrations, validators and runtime had no single supported-kind authority. | Added `SUPPORTED_WORKFLOW_NODE_KINDS` and contract snapshot enforcement. |
| Historical migration risk | Upgrade path lacked shadow fixture coverage. | Added historical SQLite compatibility fixtures under `tests/fixtures/compatibility/` and restart/read/write/rollback checks. |
| Liveness supervision | In-process health endpoints cannot detect event-loop/GIL stalls. | Added out-of-process supervisor with IPC, heartbeat, DB responsiveness and incident persistence. |
| PostgreSQL connection storms | Distributed storage needed explicit pool health/timeout/reconnect/metrics invariants. | Hardened pool usage and added high-concurrency gate script. |
| Lease clock risk | Lease/heartbeat logic used wall-clock time in paths that must survive NTP rollback/suspend/resume. | Added monotonic timebase and lease handover/fencing semantics. |
| Audit/logging failure semantics | Ordinary logging and security audit failure were not cleanly separated. | Added fail-safe async logging semantics and audit degraded/recovery policy boundaries. |
| Network partition | Lease re-acquisition could not distinguish safe handover from review-required work. | Added grace/handover/self-protection/review-required semantics. |
| Windows service hardening | Service/Desktop/User/Machine DPAPI and crash diagnostics were not unified. | Added Windows runtime diagnostics, DPAPI scope handling, service/event/minidump support wiring. |
| Hot path memory | Large object paths risked `chunks -> join` double allocation. | Added streaming IO paths and 100 MiB/500 MiB/1 GiB memory gate. |
| Future callbacks | Anonymous closures risked lifecycle retention in long-running workers. | Added explicit callback lifecycle helpers and 24h soak harness. |
| SQL identifiers | Identifier safety needed cross-database validation. | Added strict identifier validator and deterministic fuzz coverage. |
| Repair module size | `repair.py` mixed scanner/planner/executor/recovery/diagnostics concerns. | Split into responsibility modules while preserving public facade. |

## Verification Completed in This Environment

- `python -m compileall -q src scripts tests`: PASS
- Production AST `pass` scan: PASS, 0 findings
- Forbidden placeholder scan: PASS, 0 findings
- `scripts/quality_20d_gate.py`: PASS
- `scripts/workflow_contract_gate.py`: PASS
- `scripts/architecture_debt_gate.py`: PASS
- `scripts/exception_quality_gate.py`: PASS
- `scripts/strict_quality_gate.py`: PASS
- `scripts/api_contract_gate.py`: PASS
- `scripts/arenyxa_namespace_gate.py`: PASS
- `scripts/test_skip_policy_gate.py`: PASS
- `scripts/report_assertion_gate.py`: PASS after stale failed local report removal
- `scripts/production_config_gate.py`: PASS
- `scripts/performance_regression_gate.py`: PASS
- `scripts/hot_path_memory_gate.py`: PASS
- `scripts/enterprise_release_gate.py`: PASS
- `scripts/v8_acceptance_gate.py`: local engineering PASS / production certification PARTIAL
- Phase gates executed directly: Phase 1 PASS, Phase 2 PASS, Phase 3 PASS, Phase 4 PASS, Phase 6 PASS, Phase 7 PASS
- Targeted regression after final code changes: 60 passed
- Repair/source manifest regression after regeneration: 22 passed

## Performance and Memory Evidence

Hot-path memory gate:

| Input | Peak Python allocation | Result |
|---:|---:|---|
| 100 MiB | ~2.001 MiB | PASS |
| 500 MiB | ~2.001 MiB | PASS |
| 1024 MiB | ~2.001 MiB | PASS |

Performance regression gate remained healthy across 3 checked server reports.

## Environment-Gated Items Not Falsely Marked PASS

These were not executed in the Linux container and must be executed on the matching target infrastructure before a formal production release:

1. Windows PowerShell 5.1 native launch probe execution.
2. Windows Service Control Manager / DPAPI User-vs-Machine / Event Log / MiniDump runtime certification.
3. Real PostgreSQL 64-worker / 128-concurrency connection-storm test using `ARENYXA_POSTGRES_TEST_DSN`.
4. Full 24-hour future callback soak using `ARENYXA_24H_LEAK_TEST=1`.
5. `ruff`, `mypy`, `pip-audit`, and CycloneDX SBOM execution; the current container lacks these tools and cannot install them because external package resolution is unavailable.
6. Native Qt UI tests; the current container has no supported Qt binding, so Qt-only tests skip by design.

## Release Position

This source tree is a substantially industrialized v8.0 engineering candidate with the requested code, tests, gates, and documentation added. It is **not** labeled as externally production-certified because the required Windows, PostgreSQL, CVE/SBOM toolchain, and 24-hour soak gates were not available in this execution environment.


---

## Source: `TEST_EXECUTION_REPORT.md`

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


---

## Source: `TEST_REPORT.md`

# Arenyxa v8.0 beta17 Test Report

## Passed

- `compileall` for `src/arenyxa`: PASS.
- beta17 standard-library architecture suite: 7/7 PASS.
- existing navigation settings round-trip/validation regression functions: 3/3 PASS.
- existing navigation capability architecture regression functions: 6/6 PASS after adapting Enterprise-mode expectations; no test was deleted.
- focused PySide6 imports for Welcome Center, startup shell, theme transition, and MainWindow: PASS.
- `scripts/verify_beta17_release_identity.py`: PASS.
- source manifest regeneration: PASS; 1,109 files recorded.
- PEP 517 wheel build: PASS; `arenyxa-8.0.17-py3-none-any.whl`, SHA-256 `27e7678efa0e44b439710a594855701a3bf57756b52d4490f5ffd598718441c9`.

## Environment-limited checks

- Full `pytest` was requested but the supplied beta13 `.venv` points to a removed Python 3.11 executable and contains no pytest package. The available bundled Python 3.12 also has no pytest. Installation attempts did not produce a usable pytest install, so no full-suite PASS is claimed.
- The isolated `--smoke-test` reached real bootstrap and then failed in the pre-existing DPAPI key creation path with `CryptProtectData failed` under the managed sandbox identity, before MainWindow construction. MainWindow and the changed UI modules import successfully with compatible dependencies preloaded. A physical Windows user-session smoke run remains required.

## New coverage

Tests cover all five canonical modes, the eight-entry primary navigation invariant, Enterprise Console entry without identity, Developer Center entry without authority minting, event publication, settings persistence/restart restore, Personal scenario landing, and Root challenge fallback/activation.


---

## Source: `PHYSICAL_QA_RELEASE_CHECKLIST.md`

# Arenyxa v8.0 Physical QA Release Checklist

Use this checklist only for hardware-backed certification. Automated CI may verify logic and contracts, but must not mark these items as passed without a real Windows host or physical/VM lab configured for the item.

## Driver and packet capture

- Verify Npcap/dumpcap startup on Windows 10 22H2 and Windows 11 24H2.
- Verify standard-user and administrator UAC behavior.
- Verify capture startup with Defender real-time protection enabled.
- Verify long capture shutdown leaves no dumpcap/tshark orphan process.

## Installer, migration, and file locking

- Upgrade from at least one v6.8-era SQLite state and one v7.x state.
- Verify `.pre-migration.bak` recovery after forced process termination during migration.
- Verify install/uninstall under Admin and Limited User accounts.
- Verify behavior with Defender controlled-folder access or comparable file-lock pressure.

## Desktop graphics and DWM

- Verify launch animation and main window handoff on 60Hz, 120Hz, and mixed-DPI displays.
- Verify dragging between 100% and 200% scaling monitors.
- Verify Glass / Reduce Motion paths on Intel integrated GPU and NVIDIA discrete GPU.

## External services

- Run PostgreSQL 64-worker / 128-concurrency gate against a real PostgreSQL instance.
- Run the 24-hour future-callback soak with `ARENYXA_24H_LEAK_TEST=1`.
- Archive all generated JSON evidence with the release artifact.


---

## Source: `P0_P1_FINAL_FIX_REPORT.md`

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


---

## Source: `P0_P1_SECURITY_FIXES.md`

# Arenyxa v7.8 P0/P1 Security and Reliability Fixes

- Added explicit external binary version/capability contracts for tshark, dumpcap, and mitmdump.
- Required tshark schema fields are verified before capture/analysis execution.
- Hardened distributed lease recovery against renew/recover and complete/recover races.
- Added queue invariant auditing for lease ownership and worker active-lease accounting.
- Moved blocking persistence work away from the asyncio event-loop thread.
- Added bounded cancellation/finalization behavior for async request tasks.
- Added non-interactive Developer authentication using the existing signed bundle and encrypted vault model without plaintext environment-secret injection.
- Reduced and statically classified broad exception boundaries in critical execution paths.
- Raised global coverage governance and added critical-module coverage thresholds to CI.


---

## Source: `MYPY_ADVISORY_GATE_FIX_README.txt`

Arenyxa v6.6beta2 - mypy advisory gate correction

Why this patch exists
---------------------
The current codebase has a large pre-existing mypy backlog, including platform-specific
APIs (for example fcntl on POSIX), dynamic Qt compatibility facades, and other runtime
abstractions. A strict full-package mypy run therefore reports many findings that were
not introduced by the packaging change and that are already covered by runtime tests.

Release-blocking gates after this patch
---------------------------------------
- Python compileall
- Critical Ruff/Pyflakes: E9, F63, F7, F82
- Python 3.8 grammar compatibility check
- pytest

Advisory/non-blocking audits
----------------------------
- Full Ruff scan
- Full mypy scan

This does NOT suppress or erase mypy findings. They remain visible in build output and
should be reduced in a dedicated typing-hardening pass rather than being mass-edited
inside the packaging workflow.


---

## Source: `MYPY_PACKAGING_GATE_FIX_README.txt`

Arenyxa v6.6beta2 - mypy packaging gate fix

Problem fixed:
- Modern mypy no longer accepts python_version=3.8.
- The previous release gate therefore aborted before pytest/PyInstaller.
- mypy could also follow installed third-party packages such as anyio and reject
  their Python 3.10+ syntax while pretending to target Python 3.8.

New release policy:
1. compileall is blocking.
2. fatal Ruff/Pyflakes checks are blocking.
3. full Ruff is advisory.
4. all Arenyxa runtime source is parsed with Python 3.8 grammar (blocking).
5. mypy uses a dedicated Python 3.11 release config and does not scan site-packages.
6. pytest is blocking.

The real Windows 7/Python 3.8 lane remains available through scripts/test-win7.ps1.


---

## Source: `STARTUP_DIAGNOSTICS_README.txt`

Arenyxa v8.0 Startup Diagnostics

Added diagnostic-only instrumentation for startup/crash localization.

Windows log directory:
  %USERPROFILE%\Desktop\Arenyxa_Logs\

Files:
  launcher.log        - source launcher probe/spawn information
  startup.log         - JSONL startup checkpoints (BOOT-000 ... BOOT-030)
  startup_crash.log   - uncaught Python exceptions with last successful stage and full traceback
  native_fault.log    - Python faulthandler output for supported fatal/native faults

How to diagnose a flash-exit:
  1. Start Arenyxa normally once.
  2. Open startup.log and find the final BOOT stage.
  3. Check startup_crash.log for traceback.
  4. If startup_crash.log has no Python traceback, inspect native_fault.log.
  5. launcher.log confirms whether the source launcher created the Python child process.

The diagnostics layer is best-effort and does not suppress or convert application exceptions.
It does not change Security/TPM/Root/Enterprise/Server/Worker business behavior.

Fallback: if the desktop path cannot be resolved, diagnostics fall back to the existing local application log path.


---

## Source: `V7.0_WINDOWS_BUILD_GATE_HOTFIX_README.txt`

Arenyxa v7.0 Windows build-gate hotfix
=====================================

Issue
-----
The release-blocking test
`test_plugin_output_budget_is_enforced_while_child_is_running` used a 64 MiB
plugin-process memory budget while attempting to isolate the 1 KiB stdout/stderr
budget. On some Windows CPython builds, the Windows Job Object can enforce that
independent memory ceiling before the worker reaches the intended output-limit
path. The release gate then reports PLUGIN_EXECUTION_FAILED instead of the
expected PLUGIN_BUDGET_EXCEEDED.

Resolution
----------
The test now uses the production-like 256 MiB memory allowance while retaining
the 1 KiB output limit. This makes the test deterministic across supported
Windows/Linux validation environments and keeps the test focused on the output
budget it is intended to verify. Production PluginSandbox behavior and default
budgets are unchanged.

Validation
----------
- targeted output-budget test: PASS
- complete test_deep_runtime_resilience.py: PASS (32 tests)
- v7.0 product/package/installer identity remains unchanged
- startup animation sources unchanged


---

## Source: `WINDOWS_FSYNC_HOTFIX_README.txt`

Arenyxa v6.6beta2 Windows fsync hotfix

Fixes Windows startup failure:
  OSError: [Errno 9] Bad file descriptor
  database.py -> backup_to() -> os.fsync(handle.fileno())

Cause: completed artifacts were reopened read-only immediately before os.fsync().
On Windows Python implements os.fsync() through the Microsoft CRT _commit primitive;
Arenyxa now reopens completed files with a write-capable descriptor without truncation.

Also hardens the same pattern in:
- SQLite migration backups
- run exports
- project package saves
- diagnostic package exports
- source repair seed generation

Validation performed on the corrected source tree:
  332 passed, 6 skipped, 0 failed

Apply: extract this overlay into the Arenyxa source root and replace existing files.
Then run:
  .\.venv\Scripts\python.exe scripts\build_source_repair_seed.py
  .\.venv\Scripts\python.exe scripts\build_source_manifest.py
  .\.venv\Scripts\python.exe -c "from arenyxa.bootstrap import bootstrap; c=bootstrap(); print('BOOTSTRAP OK'); c.shutdown()"
  .\scripts\run.ps1


---

## Source: `WINDOWS_REPAIR_CENTER_BUTTON_COMPAT_HOTFIX_README.txt`

Arenyxa v6.6beta2 - Windows Repair Center Button Compatibility Hotfix
Date: 2026-08-10

Issue fixed:
  Opening Settings -> Repair Center could fail on Windows + PySide6 6.11.x with:
  'PySide6.QtWidgets.QWidget' object has no attribute 'setDefault'

Root cause:
  RepairSelectionDialog relied on QDialogButtonBox.addButton(text, role) returning a
  concrete QPushButton. On the affected PySide6 Windows runtime the overload result could
  be surfaced through a generic QWidget wrapper.

Fix:
  - Construct concrete QPushButton objects explicitly.
  - Set default/auto-default on the concrete start button.
  - Register the existing button objects with QDialogButtonBox.
  - Add a regression contract test.
  - Rebuild bundled repair seed/manifest and SOURCE_MANIFEST.

Validation:
  343 passed, 6 skipped, 0 failed.
  The skipped tests require a Qt binding unavailable in the Linux review environment.

Apply by copying this overlay into the existing Arenyxa v6.6beta2 source root, preserving
folders and replacing files. Then rebuild the local repair seed/source manifest if your
working tree contains additional local modifications.


---

## Source: `WINDOWS_TERMINAL_DIRECT_TEST_QUOTING_FIX_README.txt`

Arenyxa v6.6beta2 - Windows Direct Terminal Test Quoting Fix

Fixes the Windows-only pytest failure in:
  tests/test_terminal_hardening.py::test_direct_process_streams_output_and_reports_exit

Root cause:
  The test helper used shlex.quote(), which emits POSIX shell quoting. Arenyxa Direct mode
  on Windows does not invoke a POSIX shell, so the generated `python -c` payload could be
  split incorrectly and arrive at Python as a truncated expression such as `print(`.

Fix:
  - Windows: construct the command line with subprocess.list2cmdline().
  - POSIX: retain shlex.quote().
  - No production TerminalSession behavior is changed by this overlay.


---

## Source: `WINDOWS_UI_RTL_RESPONSIVENESS_HOTFIX_README.txt`

Arenyxa v6.6beta2 - Windows UI Responsiveness + Arabic RTL Layout Hotfix
Date: 2026-08-10

Purpose
-------
This overlay continues from the Windows fsync and Qt header/navigation hotfixes.
It addresses real Windows GUI feedback observed on PySide6 6.11.1:

1. Arabic no longer mirrors the complete application shell. The navigation rail,
   top toolbar order, inspector side and table geometry remain physically stable.
   Arabic bidi direction is applied to human-facing text controls only; technical
   URL/JSON/SQL/path/log fields remain LTR.
2. Page creation/navigation no longer translates the same widget tree multiple times.
   Hot locale switches translate only the visible shell + current page; hidden pages
   are translated lazily when shown.
3. Full-page snapshot cross-fades run only in High quality and only within a bounded
   pixel budget. Balanced/Efficiency use an atomic page commit to avoid GUI stalls.
4. The large top toolbar and About page disable pointer-driven glass specular effects
   and per-button opacity compositing.
5. Motion frame-pressure sampling is capped at 60 Hz instead of waking the GUI thread
   at the monitor's full 120/165/240 Hz refresh rate.
6. Windows taskbar COM progress calls are deduplicated when state/progress did not change.
7. About quick provenance refresh is throttled for rapid page revisits.

Apply
-----
Copy this overlay over the existing Arenyxa v6.6beta2 source tree, preserving paths.
Then rebuild the local integrity baselines:

  .\.venv\Scripts\python.exe .\scripts\build_source_repair_seed.py
  .\.venv\Scripts\python.exe .\scripts\build_source_manifest.py

Run directly (avoids PowerShell policy issues):

  .\.venv\Scripts\python.exe -m arenyxa

Validation baseline (Linux review environment; Qt GUI modules unavailable there):
  341 passed, 6 skipped, 0 failed across four isolated full-suite groups.
  ResourceWarning-as-error gate: same 341 passed, 6 skipped, 0 failed.

The skipped cases are Qt GUI smoke/motion tests that must be certified on the user's
real Windows + PySide6 environment. This hotfix adds static regression contracts and
updates the existing locale-direction GUI expectation for stable-shell RTL.


---

## Source: `WINDOWS_UI_SMOKE_LAZY_PAGE_FIX_README.txt`

Arenyxa v6.6beta2 UI smoke lazy-page test fix
Purpose: align test_ui_smoke.py with MainWindow lazy page construction.
Startup is expected to create dashboard only; other pages are created on navigation.
The test now verifies required routes via nav_buttons and verifies network is lazily created after navigate().


---

## Source: `docs/FINAL_QUALITY_GATE_2026-08-13.md`

# Arenyxa Final Quality Gate

`python scripts/final_quality_gate.py --full` is the release-candidate source gate.

It intentionally checks independent dimensions instead of treating a single pytest run as proof of release quality: compilation, static security, the dedicated peak-performance/resilience contract, frozen startup visuals, Welcome Center topology, UI button wiring, architecture, Web Intelligence, reliability/resource governance, Security Kernel, Developer Trust, Enterprise Identity, Enrollment/Coordinator/Governance, Enterprise Server/Worker, Phase-12 release hardening, and optionally the complete historical pytest suite.

The command stops at the first failing dimension and writes `FINAL_QUALITY_GATE.json`. A PASS is a source/automation gate only; Windows native Qt/DPI/DPAPI/Service and real multi-machine network tests remain mandatory before Enterprise/LTS GA.


---

## Source: `docs/QA_VERIFICATION_REPORT.md`

# Arenyxa v6.6 本地稳定源码工程验证报告

日期：2026-08-10

## 基线

最终工作树从用户本地稳定发布源码 `Arenyxa_V6.6_Stable_Release_Source.zip` 建立。后续品牌迁移、Developer Mode 双协议门禁、一键功能验证、压力稳定性测试及其修复均在该工作树上完成。

## 当前功能验证

- 内置 `test-all`：14/14 实际执行项通过。
- 高级能力 wiring：30/30 contract 可解析且实现方法存在。
- `stress-test quick`：最高 4 workers，0 error。
- `stress-test standard`：最高 12 workers，0 error。
- `stress-test extreme`：最高 64 workers，每级 600 次混合操作，0 error；在配置安全上限内未观察到崩溃。

## Python / 兼容性

- `compileall`：源码与测试通过。
- Python 3.8 grammar gate：87 个受检查 Python 文件通过。
- Modern / Windows 7 Legacy Qt scoped-enum 契约包含 Developer Mode 协议对话框所需的 `Ok` 映射。
- 公开入口：`python -m arenyxa --version` 输出 `Arenyxa 6.6`。
- 兼容入口：`python -m arenyxa --version` 同样输出 `Arenyxa 6.6`。
- Headless 公开入口 `python -m arenyxa.server --help` 可正常解析。

## 回归结果

在 Source Manifest 最终重生成前，所有不依赖该最终哈希文件的测试分片结果为：

- 分片 A：84 passed；
- 分片 B：122 passed，1 个 Qt 环境 skip；
- 分片 C：124 passed，4 个 Qt 环境 skip；
- 分片 D：46 passed，1 个 Qt 环境 skip；
- Source Manifest 最终哈希测试：1 passed。
- 最终同一 pytest 进程完整回归：377 passed，6 skipped，0 failed，40.39 秒；进程自然退出且未留下测试子进程。

6 个 skip 均来自当前审查环境没有受支持 Qt binding 的 GUI smoke/visual tests；这不是业务断言失败，也不能替代 Windows 原生 GUI 认证。

## Repair Seed

- Product：Arenyxa。
- 受保护文件：98。
- 新 `src/arenyxa` facade：已包含。
- 新 `developer_safety.py` / `developer_validation.py`：已包含。
- Seed SHA-256 ↔ manifest：匹配。
- ZIP CRC：通过。
- Repair Seed 内部文本禁用关键字扫描：0 命中。

## 构建产物验证

- Python wheel 成功构建：`arenyxa-6.6.0-py3-none-any.whl`。
- Wheel ZIP CRC：通过。
- Wheel 包含 Arenyxa 公共 facade、内部兼容实现、Developer Mode 双协议模块、完整功能验证模块和最新 Repair Seed。
- Wheel 不包含迁移前的旧品牌图片资源。
- Wheel 文本禁用关键字扫描：0 命中。

## 仍需原生 Windows 验证

当前容器不能诚实替代 Windows 10/11 或 Windows 7 SP1 x64 的真实 Qt、PyInstaller、Inno Setup 和系统驱动环境。正式二进制发布前必须在 Windows 上重新执行 `scripts\test.ps1` 与 `scripts\build.ps1`，并进行安装/升级/卸载、GUI、Repair Center、系统抓包与 Legacy lane 冒烟。

