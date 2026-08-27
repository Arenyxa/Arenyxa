from __future__ import annotations

from arenyxa.bootstrap import bootstrap


def test_main_window_builds_fixed_five_region_shell(qapp, tmp_path) -> None:
    from arenyxa.presentation.main_window import MainWindow

    context = bootstrap(tmp_path / "runtime", safe_mode=True)
    window = MainWindow(context)
    try:
        window.show()
        qapp.processEvents()
        assert window.nav.isVisible()
        assert window.topbar.isVisible()
        assert window.stack.isVisible()
        assert window.inspector.isVisible()
        assert window.statusBar().isVisible()
                                                                                        
                                                                                        
        required_routes = {"dashboard", "tasks", "network", "data", "advanced", "settings"}
        assert required_routes.issubset(window.nav_buttons)
        assert "dashboard" in window.pages
        assert "network" not in window.pages

        assert window.windowIcon().isNull() is False
        window.navigate("network")
        qapp.processEvents()
        assert window.current_page_id == "network"
        assert "network" in window.pages
    finally:
        window.save_window_state()
        context.shutdown()
        window.deleteLater()
        qapp.processEvents()


def test_navigation_page_buttons_are_exclusive(qapp, tmp_path) -> None:
    from arenyxa.presentation.main_window import MainWindow

    context = bootstrap(tmp_path / "runtime-exclusive-nav", safe_mode=True)
    window = MainWindow(context)
    try:
        window.show()
        qapp.processEvents()
        assert window.nav_button_group.exclusive() is True

        def checked_ids() -> list[str]:
            return [page_id for page_id, button in window.nav_buttons.items() if button.isChecked()]

        assert checked_ids() == ["dashboard"]

        window.nav_buttons["network"].click()
        qapp.processEvents()
        assert window.current_page_id == "network"
        assert checked_ids() == ["network"]

        window.nav_buttons["data"].click()
        qapp.processEvents()
        assert window.current_page_id == "data"
        assert checked_ids() == ["data"]

                                                                                     
                               
        window.nav_buttons["data"].click()
        qapp.processEvents()
        assert checked_ids() == ["data"]
    finally:
        context.shutdown()
        window.deleteLater()
        qapp.processEvents()


def test_sidebar_footer_is_pinned_and_revision_compare_caps_selection(qapp, tmp_path) -> None:
    from arenyxa.presentation.main_window import MainWindow
    from arenyxa.presentation.pages.data import VersionPage

    context = bootstrap(tmp_path / "runtime-v652-sidebar", safe_mode=True)
    window = MainWindow(context)
    try:
        window.show()
        qapp.processEvents()
        assert window.nav.width() == 236
        assert window.nav_footer.parent() is window.nav
        assert window.service_label.parent() is window.nav_footer
        assert window.nav_buttons["settings"].parent() is window.nav_footer
        assert window.nav_buttons["about"].parent() is window.nav_footer
        assert all(button.icon().isNull() is False for button in window.nav_buttons.values())

        window.navigate("version")
        qapp.processEvents()
        page = window.pages["version"]
        assert isinstance(page, VersionPage)
        page.list.clear()
        page._revision_selection_order.clear()
        for label in ("r1", "r2", "r3"):
            page.list.addItem(label)
        for row in range(3):
            page.list.item(row).setSelected(True)
            qapp.processEvents()
        assert len(page.list.selectedItems()) <= 2
    finally:
        context.shutdown()
        window.deleteLater()
        qapp.processEvents()
