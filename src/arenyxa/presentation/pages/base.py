from __future__ import annotations

from arenyxa.bootstrap import ApplicationContext
from arenyxa.presentation.motion import MotionOrchestrator
from arenyxa.presentation.themes import ThemeManager
from arenyxa.qt_compat.QtCore import Qt, Signal
from arenyxa.qt_compat.QtWidgets import QVBoxLayout, QWidget


class WorkspacePage(QWidget):
    inspectorChanged = Signal(str, object)
    statusMessage = Signal(str)
                                                                             
    operationProgress = Signal(str, int, int, str)

    def __init__(
        self,
        context: ApplicationContext,
        theme: ThemeManager,
        motion: MotionOrchestrator,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.context = context
        self.theme = theme
        self.motion = motion
        self._page_active = False
                                                                                            
                                                                                                 
        self.setProperty("arenyxa_shell_ltr", True)
        self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)

    def activated(self) -> None:
        self._page_active = True
        self.setProperty("arenyxa_page_active", True)

    def deactivated(self) -> None:
        self._page_active = False
        self.setProperty("arenyxa_page_active", False)


def page_layout(widget: QWidget) -> QVBoxLayout:
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(12)
    return layout
