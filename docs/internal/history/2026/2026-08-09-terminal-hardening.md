# Arenyxa V6.0 Developer Terminal Hardening — 2026-08-09

## Scope

The former Terminal & Packet Console executed one bounded subprocess at a time using a `!` prefix. The hardened implementation keeps the Developer Mode and per-command confirmation boundary, while turning the page into a practical project developer console.

## Execution modes

- **Arenyxa Console** — internal commands only; no operating-system process is started.
- **Direct Process** — starts an executable directly with `shell=False`; pipes, redirection and command chaining are not interpreted.
- **PowerShell** — explicit full-shell mode with PowerShell syntax, UTF-8 output and an additional warning surface.
- **CMD** — Windows full-shell mode with UTF-8 code page initialization.
- **Python** — one-shot `python -u -c` execution using the current Arenyxa interpreter.

Backward compatibility is retained: `!command` selects Direct Process and `!!command` selects PowerShell.

## Session capabilities

The console now maintains application-managed session state across commands:

- project working directory with `pwd`, `cd`, and `ls`;
- strict confinement to the Arenyxa `Projects` root, including resolved symlink/path traversal checks;
- session-only environment variables through `env`, `setenv`, and `unsetenv`;
- sensitive environment values are redacted;
- session-only command history with Up/Down navigation and adjacent-duplicate suppression;
- command completion for Arenyxa built-ins;
- executable discovery with `which`;
- configurable per-process timeout from 1 to 3600 seconds;
- process status, version, application paths and active capture status;
- bounded task, Run, Capture and network-event queries;
- read-only SQLite console (`SELECT`, `PRAGMA`, `EXPLAIN`, `WITH`) with a 500-row cap;
- `stdin <text>` and `eof` for processes that accept standard input.

## Process lifecycle

External commands now stream output incrementally instead of waiting for process completion. The console displays exit code and duration, supports a Stop button, and applies the following safeguards:

- one external process per Arenyxa terminal session;
- default 300-second timeout, configurable per session;
- 2,000,000-character per-process output budget to prevent runaway output from exhausting GUI memory;
- process-group termination on POSIX;
- Windows process-group break plus `taskkill /T /F` fallback to avoid orphaned child processes;
- application shutdown terminates the active terminal process;
- disabling Developer Mode immediately terminates an active external process.

## Security model

Developer Mode remains the authority boundary. Arenyxa internal commands work without external process execution, while Direct/PowerShell/CMD/Python execution requires Developer Mode and explicit confirmation for every command.

Direct Process remains the safest external mode because it does not invoke a command shell. PowerShell and CMD intentionally support pipelines, redirection, variable expansion and command chaining and therefore display a stronger warning. Python mode also receives a stronger warning because arbitrary Python code runs with the current user's permissions.

A lightweight risk classifier highlights deletion, disk-management, boot-configuration, shutdown and privilege-elevation patterns. It does not pretend to be a security sandbox; it adds an extra warning while preserving developer freedom.

Commands are redacted before they are echoed to the console or stored in session history. Bearer tokens, API keys, passwords, secrets, authorization headers and cookie headers are replaced with `<redacted>` where recognized. Command history is intentionally not persisted to disk.

## SQLite console

The SQL path opens the Arenyxa database using SQLite URI `mode=ro`, and accepts only statements beginning with `SELECT`, `PRAGMA`, `EXPLAIN`, or `WITH`. Results are bounded to 500 rows before they reach the GUI output pipeline. The `sql tables` convenience command lists user tables and views.

## Verification

`tests/test_terminal_hardening.py` covers:

- Projects-root path confinement;
- environment redaction and validation;
- secret redaction in command history;
- bounded history;
- read-only SQL and write rejection;
- risk classification;
- real-time direct-process output;
- timeout termination;
- user cancellation;
- runaway-output protection;
- standard-input delivery;
- non-blocking GUI cancellation;
- observer callback failure cleanup.

The terminal service lives in `src/arenyxa/application/terminal.py`, independently of Qt, so lifecycle and security behaviour can be tested in headless environments. The GUI integration remains in `src/arenyxa/presentation/pages/tools.py`.

## Deliberate limits

This hardening pass does **not** claim to implement a full ConPTY/PTY terminal emulator. PowerShell/CMD/Python execution is process based: Arenyxa preserves its own cwd/environment/history state, but shell-local aliases, functions and variables created inside one one-shot command are not automatically preserved into the next command. Full-screen TUI applications that require a real console device may therefore not behave like Windows Terminal or VS Code Terminal. `stdin` covers line-oriented interactive programs without weakening the current safety boundary. `stdin-secret` provides a non-echoing path for sensitive line input. Ctrl+C (when no text selection exists) requests process cancellation, and Ctrl+L clears the console.
