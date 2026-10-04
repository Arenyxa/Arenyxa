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
