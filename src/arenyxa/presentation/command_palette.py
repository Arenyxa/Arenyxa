from __future__ import annotations

"""Command palette widget shared by the main-window operation mixin."""

from collections.abc import Callable

from arenyxa.qt_compat.QtCore import Qt, QTimer
from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QLineEdit,
    QListWidget,
    QVBoxLayout,
    QWidget,
)


class CommandPalette(QDialog):
    """Search and invoke shell commands without coupling mixins to MainWindow."""

    def __init__(
        self,
        commands: list[tuple[str, str, Callable[[], None]]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Command Palette")
        self.setModal(True)
        self.resize(560, 430)
        self.commands = commands
        layout = QVBoxLayout(self)
        self.query = QLineEdit()
        self.query.setPlaceholderText("输入命令或页面名称")
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        layout.addWidget(self.query)
        layout.addWidget(self.list, 1)
        self.query.textChanged.connect(self.refresh)
        self.list.itemActivated.connect(self.execute_current)
        self.refresh()
        QTimer.singleShot(0, self.query.setFocus)

    def refresh(self) -> None:
        query = self.query.text().casefold()
        self.list.clear()
        for command_id, label, callback in self.commands:
            if query in label.casefold() or query in command_id.casefold():
                self.list.addItem(label)
                self.list.item(self.list.count() - 1).setData(
                    Qt.ItemDataRole.UserRole,
                    (command_id, callback),
                )
        if self.list.count():
            self.list.setCurrentRow(0)

    def execute_current(self) -> None:
        item = self.list.currentItem()
        if not item:
            return
        _, callback = item.data(Qt.ItemDataRole.UserRole)
        self.accept()
        callback()


__all__ = ["CommandPalette"]
