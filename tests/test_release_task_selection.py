from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from arenyxa.domain.models import Task
from arenyxa.presentation.main_window_operations import MainWindowOperationsMixin
from arenyxa.presentation.pages.tasks import TasksPage
from arenyxa.qt_compat.QtWidgets import QPushButton


class WindowHarness(SimpleNamespace):
    pass


@pytest.fixture
def task_page(qapp):
    tasks = [Task(name="first unrelated task", requests=[]), Task(name="explicitly selected task", requests=[])]
    context = SimpleNamespace(store=SimpleNamespace(list_tasks=lambda **_: tasks))
    page = TasksPage(context, None, None)
    page.resize(940, 640)
    page.refresh()
    page.show()
    qapp.processEvents()
    yield page, tasks
    page.close()
    page.deleteLater()
    qapp.processEvents()


def test_toolbar_runs_selected_row_through_existing_preflight(task_page):
    page, tasks = task_page
    page.table.selectRow(1)
    page.run_task = Mock()
    window = WindowHarness(pages={"tasks": page}, context=Mock(), navigate=Mock(), show_status=Mock())
    window.context.store.list_tasks.return_value = tasks
    MainWindowOperationsMixin.run_selected_task(window)
    page.run_task.assert_called_once_with(tasks[1], False)
    window.context.runner.submit.assert_not_called()
    window.context.store.list_tasks.assert_not_called()


@pytest.mark.parametrize("page_present", [True, False])
def test_toolbar_never_submits_unselected_task(task_page, page_present):
    page, tasks = task_page
    page.table.clearSelection()
    page.run_task = Mock()
    window = WindowHarness(pages={"tasks": page} if page_present else {}, context=Mock(), navigate=Mock(), show_status=Mock())
    window.context.store.list_tasks.return_value = tasks
    MainWindowOperationsMixin.run_selected_task(window)
    page.run_task.assert_not_called()
    window.context.runner.submit.assert_not_called()
    window.context.store.list_tasks.assert_not_called()
    window.navigate.assert_called_once_with("tasks")


def test_task_actions_fit_text_and_row_height(task_page, qapp):
    page, _ = task_page
    actions = page.table.cellWidget(0, 5)
    qapp.processEvents()
    buttons = actions.findChildren(QPushButton)
    assert len(buttons) == 3
    for button in buttons:
        assert button.width() >= button.minimumSizeHint().width()
        assert button.height() >= button.minimumSizeHint().height()
    assert page.table.rowHeight(0) >= actions.minimumSizeHint().height()


def test_refresh_does_not_retarget_selection(task_page):
    page, tasks = task_page
    page.table.selectRow(1)
    assert page.selected_task().id == tasks[1].id
    page.context.store.list_tasks = lambda **_: [tasks[1], tasks[0]]
    page.refresh()
    selected = page.selected_task()
    assert selected is None or selected.id == tasks[1].id


def test_mouse_selection_without_action_cell_item_is_resolved(task_page, qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    page, tasks = task_page
    point = page.table.visualItemRect(page.table.item(1, 0)).center()
    QTest.mouseClick(page.table.viewport(), Qt.MouseButton.LeftButton, pos=point)
    qapp.processEvents()
    assert page.selected_task() is tasks[1]


def test_selection_works_when_qt_owned_selection_wrapper_is_unavailable(task_page, monkeypatch):
    page, tasks = task_page
    page.table.selectRow(1)
    monkeypatch.setattr(page.table, "selectionModel", lambda: None)
    assert page.selected_task() is tasks[1]


def test_action_layout_when_header_wrapper_cannot_resize(qapp, monkeypatch):
    import arenyxa.presentation.pages.tasks as tasks_module

    monkeypatch.setattr(tasks_module, "set_table_header_resize_mode", lambda *_: False)
    context = SimpleNamespace(store=SimpleNamespace(list_tasks=lambda **_: [Task(name="fallback", requests=[])]))
    page = TasksPage(context, None, None)
    try:
        page.resize(940, 640)
        page.refresh()
        page.show()
        qapp.processEvents()
        actions = page.table.cellWidget(0, 5)
        for button in actions.findChildren(QPushButton):
            assert button.width() >= button.minimumSizeHint().width()
            assert button.height() >= button.minimumSizeHint().height()
    finally:
        page.close()
        page.deleteLater()
        qapp.processEvents()
