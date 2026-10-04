# Arenyxa Final Quality Gate

`python scripts/final_quality_gate.py --full` is the release-candidate source gate.

It intentionally checks independent dimensions instead of treating a single pytest run as proof of release quality: compilation, static security, the dedicated peak-performance/resilience contract, frozen startup visuals, Welcome Center topology, UI button wiring, architecture, Web Intelligence, reliability/resource governance, Security Kernel, Developer Trust, Enterprise Identity, Enrollment/Coordinator/Governance, Enterprise Server/Worker, Phase-12 release hardening, and optionally the complete historical pytest suite.

The command stops at the first failing dimension and writes `FINAL_QUALITY_GATE.json`. A PASS is a source/automation gate only; Windows native Qt/DPI/DPAPI/Service and real multi-machine network tests remain mandatory before Enterprise/LTS GA.
