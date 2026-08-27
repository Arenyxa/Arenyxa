from __future__ import annotations

from typing import Any

from arenyxa.qt_compat.QtCore import QRectF, Qt, Signal
from arenyxa.qt_compat.QtGui import QColor, QPainter, QPen
from arenyxa.qt_compat.QtWidgets import QWidget


class FlowGraphCanvas(QWidget):
    nodeSelected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._graph: dict[str, Any] = {"nodes": [], "edges": [], "width": 640, "height": 360}
        self._selected = ""
        self._rects: dict[str, QRectF] = {}
        self.setMinimumSize(640, 360)
        self.setMouseTracking(True)

    def set_graph(self, graph: dict[str, Any]) -> None:
        self._graph = dict(graph)
        self.setMinimumSize(int(graph.get("width") or 640), int(graph.get("height") or 360))
        self.update()

    def selected_node(self) -> str:
        return self._selected

    def select_node(self, node_id: str) -> None:
        self._selected = str(node_id)
        self.update()

    def mousePressEvent(self, event: Any) -> None:
        position = event.position() if hasattr(event, "position") else event.pos()
        for node_id, rect in self._rects.items():
            if rect.contains(position):
                self._selected = node_id
                self.nodeSelected.emit(node_id)
                self.update()
                return
        super().mousePressEvent(event)

    def paintEvent(self, _event: Any) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        nodes = list(self._graph.get("nodes") or [])
        edges = list(self._graph.get("edges") or [])
        self._rects = {}
        centers: dict[str, tuple[float, float]] = {}
        for node in nodes:
            x = float(node.get("x") or 0)
            y = float(node.get("y") or 0)
            rect = QRectF(x, y, 180, 72)
            node_id = str(node.get("id") or "")
            self._rects[node_id] = rect
            centers[node_id] = (rect.center().x(), rect.center().y())
        for edge in edges:
            source = centers.get(str(edge.get("source") or ""))
            target = centers.get(str(edge.get("target") or ""))
            if source is None or target is None:
                continue
            failure = str(edge.get("edge_type") or "") == "failure"
            painter.setPen(QPen(QColor(190, 84, 96) if failure else QColor(105, 125, 160), 2.0))
            start_x = source[0] + 90
            end_x = target[0] - 90
            mid_x = (start_x + end_x) / 2
            path = __import__("arenyxa.qt_compat.QtGui", fromlist=["QPainterPath"]).QPainterPath()
            path.moveTo(start_x, source[1])
            path.cubicTo(mid_x, source[1], mid_x, target[1], end_x, target[1])
            painter.drawPath(path)
        for node in nodes:
            node_id = str(node.get("id") or "")
            rect = self._rects[node_id]
            selected = node_id == self._selected
            painter.setPen(QPen(QColor(92, 126, 230) if selected else QColor(90, 99, 116), 2.5 if selected else 1.5))
            painter.setBrush(QColor(38, 42, 52, 235) if not selected else QColor(49, 60, 90, 245))
            painter.drawRoundedRect(rect, 13, 13)
            painter.setPen(QColor(235, 238, 245))
            title = str(node.get("id") or "")[:28]
            kind = str(node.get("kind") or "")[:30]
            painter.drawText(rect.adjusted(12, 8, -12, -34), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, title)
            painter.setPen(QColor(160, 170, 190))
            painter.drawText(rect.adjusted(12, 36, -12, -8), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, kind)
        painter.end()
