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
