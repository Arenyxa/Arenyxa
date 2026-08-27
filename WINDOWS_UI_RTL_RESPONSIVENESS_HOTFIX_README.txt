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
