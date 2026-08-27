# Arenyxa v6.8 Phase 0 — Known Limitations

Date: 2026-08-12

1. **Native Windows visual behavior cannot be certified by a Linux/headless environment.** Offscreen Qt can test contracts and geometry math but not DWM/compositor timing, actual monitor handoff, taskbar focus behavior, per-monitor DPI transitions, or the final X-style startup feel.
2. **Packet capture depends on the native capture stack.** Browser/tshark/Npcap lifecycle must be smoke-tested on the intended Windows host; absence of that stack in an automated environment is not proof of failure or success.
3. **Windows 7 Legacy Enterprise remains a compatibility lane, not a promise that every optional modern browser feature is available.** The shared HTTP/Dataset/Workflow/SQLite/terminal/scheduler/headless core remains the intended compatibility surface.
4. **Stress testing is intentionally bounded.** Standard/Extreme profiles validate local runtime/resource behavior and stop at safety limits; they are not intended to maximize load or destabilize the operating system.
5. **No Phase 1+ feature is included.** Architecture/contract freeze, Web Intelligence 2.x, Security Foundation, Developer Authority, Enterprise Identity and Server/Worker work remain outside this package.
