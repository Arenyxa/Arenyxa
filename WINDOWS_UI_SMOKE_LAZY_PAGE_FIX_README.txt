Arenyxa v6.6beta2 UI smoke lazy-page test fix
Purpose: align test_ui_smoke.py with MainWindow lazy page construction.
Startup is expected to create dashboard only; other pages are created on navigation.
The test now verifies required routes via nav_buttons and verifies network is lazily created after navigate().
