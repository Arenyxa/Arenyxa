from __future__ import annotations
from arenyxa.presentation.pages.dashboard_widgets import Sparkline, DashboardMetricCard, ProgressTrend, DonutChart

import json
import logging
import math
import sqlite3
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse

from arenyxa.qt_compat.QtCore import QPointF, QRectF, Qt
from arenyxa.qt_compat.QtGui import QColor, QPainter, QPainterPath, QPen
from arenyxa.qt_compat.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from arenyxa.compat import strict_zip
from arenyxa.presentation.glass import GlassPanel
from arenyxa.presentation.language import literal_for_locale
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import RingGauge, SectionCard, format_bytes


LOGGER = logging.getLogger(__name__)












class DashboardPage(WorkspacePage):
    

    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        outer = page_layout(self)
        outer.setSpacing(10)
        outer.addWidget(self._build_title_bar())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        container = QWidget()
        container.setMinimumWidth(1020)
        self.grid = QGridLayout(container)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(10)
        self.grid.setVerticalSpacing(10)
        scroll.setWidget(container)
        outer.addWidget(scroll, 1)

        self._index_snapshot_error_reported = False
        self.metric_cards: dict[str, DashboardMetricCard] = {}
        metric_specs = [
            ("records", "已索引页面", "▤", "0", "本地结构化结果", "success", True),
            ("database", "存储大小（估算）", "▣", "0 B", "本地数据库", "info", True),
            ("last_run", "上次抓取时间", "◷", "暂无", "尚无运行记录", "warning", False),
            ("storage_mode", "存储模式", "▥", "磁盘存储", "本地文件系统", "accent", False),
            ("active", "活动任务", "☷", "0", "无任务运行", "info", False),
            ("service", "本地服务", "◎", "在线", "http://127.0.0.1:8787", "success", False),
        ]
        for index, (key, title, symbol, value, detail, role, spark) in enumerate(metric_specs):
            card = DashboardMetricCard(theme, motion, title, symbol, value, detail, role, spark)
            self.metric_cards[key] = card
            self.grid.addWidget(card, 0, index * 2, 1, 2)

        self.task_card = SectionCard(theme, "☷  任务队列状态", "查看全部任务")
        self.task_rows = QVBoxLayout()
        self.task_rows.setSpacing(2)
        self.task_card.body.addLayout(self.task_rows)
        self.grid.addWidget(self.task_card, 1, 0, 2, 5)

        self.capture_card = SectionCard(theme, "↗  抓取进度")
        self.capture_card.setMinimumHeight(310)
        capture_top = QHBoxLayout()
        capture_top.setSpacing(18)
        self.capture_gauge = RingGauge(theme, 0, "总体进度")
        self.capture_gauge.setMinimumSize(145, 145)
        capture_top.addWidget(self.capture_gauge)
        capture_stats = QVBoxLayout()
        capture_stats.setSpacing(7)
        self.capture_labels: dict[str, QLabel] = {}
        for key, caption in (
            ("discovered", "已发现页面"),
            ("indexed", "已索引页面"),
            ("speed", "当前速度"),
            ("average", "平均速度"),
            ("errors", "错误数"),
        ):
            row = QHBoxLayout()
            name = QLabel(caption)
            name.setProperty("muted", True)
            value = QLabel("—")
            value.setStyleSheet("font-weight: 650;")
            row.addWidget(name)
            row.addStretch()
            row.addWidget(value)
            capture_stats.addLayout(row)
            self.capture_labels[key] = value
        capture_top.addLayout(capture_stats, 1)
        self.capture_card.body.addLayout(capture_top)
        self.progress_trend = ProgressTrend(theme, motion)
        self.capture_card.body.addWidget(self.progress_trend)
        current = QHBoxLayout()
        current_label = QLabel("当前任务：")
        current_label.setProperty("muted", True)
        self.current_task = QLabel("暂无活动任务")
        self.current_task.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        current.addWidget(current_label)
        current.addWidget(self.current_task, 1)
        self.capture_percent = QLabel("0%")
        self.capture_percent.setProperty("accent", True)
        current.addWidget(self.capture_percent)
        self.capture_card.body.addLayout(current)
        self.capture_progress = QProgressBar()
        self.capture_progress.setRange(0, 100)
        self.capture_progress.setTextVisible(False)
        self.capture_progress.setFixedHeight(6)
        self.capture_card.body.addWidget(self.capture_progress)
        self.grid.addWidget(self.capture_card, 1, 5, 2, 4)

        self.schedule_card = SectionCard(theme, "▣  定时任务", "查看全部")
        self.schedule_rows = QVBoxLayout()
        self.schedule_rows.setSpacing(3)
        self.schedule_card.body.addLayout(self.schedule_rows)
        self.grid.addWidget(self.schedule_card, 1, 9, 1, 3)

        self.search_card = SectionCard(theme, "⌕  最近搜索", "查看全部")
        self.search_rows = QVBoxLayout()
        self.search_rows.setSpacing(3)
        self.search_card.body.addLayout(self.search_rows)
        self.grid.addWidget(self.search_card, 2, 9, 2, 3)

        self.stats_card = SectionCard(theme, "▥  数据统计")
        stats = QHBoxLayout()
        stats.setSpacing(16)
        self.donut = DonutChart(theme, motion)
        stats.addWidget(self.donut)
        self.file_legend = QVBoxLayout()
        self.file_legend.setSpacing(6)
        stats.addLayout(self.file_legend, 1)
        stats.addWidget(self._vertical_separator())
        domain_box = QVBoxLayout()
        domain_title = QLabel("热门域名")
        domain_title.setStyleSheet("font-weight: 650;")
        domain_box.addWidget(domain_title)
        self.domain_rows = QVBoxLayout()
        self.domain_rows.setSpacing(6)
        domain_box.addLayout(self.domain_rows)
        domain_box.addStretch()
        stats.addLayout(domain_box, 2)
        stats.addWidget(self._vertical_separator())
        size_box = QVBoxLayout()
        size_title = QLabel("各类型内容大小")
        size_title.setStyleSheet("font-weight: 650;")
        size_box.addWidget(size_title)
        self.size_rows = QVBoxLayout()
        self.size_rows.setSpacing(7)
        size_box.addLayout(self.size_rows)
        size_box.addStretch()
        stats.addLayout(size_box, 2)
        self.stats_card.body.addLayout(stats)
        self.grid.addWidget(self.stats_card, 3, 0, 1, 9)

        self._wire_dashboard_actions()
        for column in range(12):
            self.grid.setColumnStretch(column, 1)
        self.grid.setRowStretch(3, 1)

    def _build_title_bar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 2)
        layout.setSpacing(10)
        title_stack = QVBoxLayout()
        title_stack.setSpacing(1)
        title = QLabel("⌁  仪表盘")
        title.setStyleSheet("font-size: 21px; font-weight: 720;")
        subtitle = QLabel("概览您的本地网页索引与系统状态")
        subtitle.setProperty("muted", True)
        title_stack.addWidget(title)
        title_stack.addWidget(subtitle)
        layout.addLayout(title_stack)
        layout.addStretch()

        self.start_button = QPushButton("▷  开始抓取")
        self.start_button.setProperty("primary", True)
        self.pause_button = QPushButton("Ⅱ  暂停")
        self.stop_button = QPushButton("■  停止")
        self.stop_button.setProperty("danger", True)
        self.search_button = QPushButton("⌕  打开搜索页面")
        self.data_button = QPushButton("▣  打开数据文件夹")
        for button in (self.start_button, self.pause_button, self.stop_button, self.search_button, self.data_button):
            layout.addWidget(button)
        return bar

    @staticmethod
    def _vertical_separator() -> QFrame:
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.VLine)
        separator.setFrameShadow(QFrame.Shadow.Plain)
        separator.setProperty("muted", True)
        return separator

    def _wire_dashboard_actions(self) -> None:
        self.start_button.clicked.connect(lambda: self._call_window("run_selected_task"))
        self.pause_button.clicked.connect(lambda: self._call_window("pause_active"))
        self.stop_button.clicked.connect(lambda: self._call_window("stop_active"))
        self.search_button.clicked.connect(lambda: self._navigate("search"))
        self.data_button.clicked.connect(lambda: self._call_window("open_data_folder"))
        if self.task_card.action:
            self.task_card.action.clicked.connect(lambda: self._navigate("tasks"))
        if self.schedule_card.action:
            self.schedule_card.action.clicked.connect(lambda: self._navigate("automation"))
        if self.search_card.action:
            self.search_card.action.clicked.connect(lambda: self._navigate("search"))

    def _call_window(self, method_name: str) -> None:
        window = self.window()
        callback = getattr(window, method_name, None)
        if callable(callback):
            callback()
        else:
            self.statusMessage.emit("当前窗口暂不支持此操作")

    def _navigate(self, page_id: str) -> None:
        window = self.window()
        callback = getattr(window, "navigate", None)
        if callable(callback):
            callback(page_id)

    def activated(self) -> None:
        metrics = self.context.store.dashboard_metrics()
        run_limit = 10 if self.context.performance.mode == "efficiency" else 14 if self.context.performance.mode == "balanced" else 18
        runs = self.context.store.list_runs(limit=run_limit)
        latest = runs[0] if runs else None
        active_handles = self.context.runner.active_handles()
        active_run = active_handles[0].run if active_handles else None

        series = [float(max(0, run.get("result_count", 0))) for run in reversed(runs[:14])]
        if len(series) < 2:
            series = [0, max(1, metrics["records"])]
        records_card = self.metric_cards["records"]
        records_card.detail.setText(f"+{max(0, latest.get('result_count', 0) if latest else 0):,}  vs 上次抓取")
        records_card.sparkline.set_values(series)
        self.motion.animate_number(records_card.value, float(metrics["records"]), lambda value: f"{int(round(value)):,}")

        database_card = self.metric_cards["database"]
        database_card.detail.setText("SQLite + 本地捕获数据")
        database_card.sparkline.set_values([max(1.0, value + 1) for value in series])
        self.motion.animate_number(database_card.value, float(metrics["database_bytes"]), lambda value: format_bytes(int(max(0, value))))
        if latest:
            last_dt = self._format_datetime(latest.get("finished_at") or latest.get("created_at"))
            duration = self._duration_text(latest)
            self.metric_cards["last_run"].set_metric(last_dt, f"耗时：{duration}")
        else:
            self.metric_cards["last_run"].set_metric("暂无", "尚无运行记录")
        self.metric_cards["storage_mode"].set_metric("磁盘存储", "本地文件系统 · 持久化")
        queued = max(0, metrics["tasks"] - metrics["active"])
        active_card = self.metric_cards["active"]
        active_card.detail.setText(f"运行中 · 共 {queued} 个排队")
        self.motion.animate_number(active_card.value, float(metrics["active"]), lambda value: str(int(round(value))))
        self.metric_cards["service"].set_metric("在线", "http://127.0.0.1:8787")

        self._rebuild_tasks(runs)
        self._refresh_capture(metrics, runs, active_run)
        self._rebuild_schedules()
        snapshot = self._load_index_snapshot()
        self._rebuild_recent_search(snapshot["recent_items"])
        self._rebuild_stats(snapshot, metrics["database_bytes"])
        self.inspectorChanged.emit("仪表盘上下文", metrics)

    def _rebuild_tasks(self, runs: list[dict]) -> None:
        self._clear_layout(self.task_rows)
        tasks = self.context.store.list_tasks(limit=5)
        latest_by_task: dict[str, dict] = {}
        for run in runs:
            latest_by_task.setdefault(str(run.get("task_id", "")), run)
        if not tasks:
            label = QLabel("尚无任务。使用“抓取任务”建立第一个采集任务。")
            label.setProperty("muted", True)
            label.setWordWrap(True)
            self.task_rows.addWidget(label)
            self.task_rows.addStretch()
            return
        animated_rows = []
        for task in tasks:
            run = latest_by_task.get(task.id, {})
            completed = int(run.get("completed_units") or 0)
            total = int(run.get("total_units") or max(1, len(task.requests)))
            percent = round(completed * 100 / total) if total else 0
            status = str(run.get("status") or task.status.value)
            url = task.requests[0].url if task.requests else "无 URL"
            row_widget = QWidget()
            row = QHBoxLayout(row_widget)
            row.setContentsMargins(0, 5, 0, 5)
            row.setSpacing(9)
            icon = QLabel("◎")
            icon.setProperty("accent", True)
            icon.setFixedWidth(18)
            row.addWidget(icon)
            text = QVBoxLayout()
            text.setSpacing(1)
            title = QLabel(url)
            title.setStyleSheet("font-weight: 610;")
            title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            meta = QLabel(f"深度：{max(1, len(task.requests))}  ·  优先级：中")
            meta.setProperty("muted", True)
            meta.setStyleSheet("font-size: 10px;")
            text.addWidget(title)
            text.addWidget(meta)
            row.addLayout(text, 1)
            state = QLabel(self._status_label(status, percent))
            state.setProperty("accent", status in {"running", "completed", "partial"})
            state.setProperty("muted", status not in {"running", "completed", "partial"})
            row.addWidget(state)
            self.task_rows.addWidget(row_widget)
            animated_rows.append(row_widget)
        self.task_rows.addStretch()
        self.motion.reveal_staggered(animated_rows, 28)

    def _refresh_capture(self, metrics: dict, runs: list[dict], active_run) -> None:
        if active_run is not None:
            completed = int(active_run.completed_units)
            total = int(active_run.total_units)
            result_count = int(active_run.result_count)
            error_count = int(active_run.failure_count)
            started_at = active_run.started_at
            current_url = self._run_url(active_run.task_snapshot)
        elif runs:
            run = runs[0]
            completed = int(run.get("completed_units") or 0)
            total = int(run.get("total_units") or 0)
            result_count = int(run.get("result_count") or 0)
            error_count = int(run.get("failure_count") or 0)
            started_at = run.get("started_at")
            try:
                snapshot = json.loads(run.get("snapshot_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                snapshot = {}
            current_url = self._run_url(snapshot)
        else:
            completed = 0
            total = 0
            result_count = 0
            error_count = 0
            started_at = None
            current_url = "暂无活动任务"

        percent = round(completed * 100 / total) if total else (100 if runs and runs[0].get("status") == "completed" else 0)
        speed = self._run_speed(completed, started_at)
        discovered = metrics["records"] + max(result_count, total)
        gauge_start = float(getattr(self.capture_gauge, "value", 0.0))
        self.motion.animate_scalar(self.capture_gauge, "gauge", gauge_start, float(percent), self.capture_gauge.set_value, 420, live=True)
        self.motion.animate_progress(self.capture_progress, percent, 420)
        self.motion.animate_number(self.capture_percent, float(percent), lambda value: f"{int(round(value))}%", 360)
        self.current_task.setText(current_url or "暂无活动任务")
        self.motion.animate_number(self.capture_labels["discovered"], float(discovered), lambda value: f"{int(round(value)):,}")
        self.motion.animate_number(self.capture_labels["indexed"], float(metrics['records']), lambda value: f"{int(round(value)):,}")
        self.motion.animate_number(self.capture_labels["speed"], float(speed), lambda value: f"{value:.1f} pages/s")
        self.motion.animate_number(self.capture_labels["average"], float(max(0.0, speed * 0.78)), lambda value: f"{value:.1f} pages/s")
        self.motion.animate_number(self.capture_labels["errors"], float(error_count + metrics["errors"]), lambda value: str(int(round(value))))
        trend = [float(max(0, run.get("completed_units") or run.get("result_count") or 0)) for run in reversed(runs[:18])]
        if len(trend) < 2:
            trend = [0, completed or 1]
        self.progress_trend.set_values(trend)

    def _rebuild_schedules(self) -> None:
        self._clear_layout(self.schedule_rows)
        schedules = self.context.store.list_schedules()[:3]
        if not schedules:
            label = QLabel("暂无定时任务")
            label.setProperty("muted", True)
            self.schedule_rows.addWidget(label)
            self.schedule_rows.addStretch()
            return
        animated_rows = []
        for schedule in schedules:
            row_widget = QWidget()
            row = QHBoxLayout(row_widget)
            row.setContentsMargins(0, 5, 0, 5)
            clock = QLabel("◷")
            clock.setProperty("accent", bool(schedule.get("enabled")))
            row.addWidget(clock)
            text = QVBoxLayout()
            text.setSpacing(1)
            name = QLabel(str(schedule.get("task_name") or "定时抓取"))
            name.setStyleSheet("font-weight: 610;")
            next_run = QLabel(self._schedule_text(schedule))
            next_run.setProperty("muted", True)
            next_run.setStyleSheet("font-size: 10px;")
            text.addWidget(name)
            text.addWidget(next_run)
            row.addLayout(text, 1)
            state = QLabel("●" if schedule.get("enabled") else "○")
            state.setProperty("accent", bool(schedule.get("enabled")))
            state.setProperty("muted", not bool(schedule.get("enabled")))
            row.addWidget(state)
            self.schedule_rows.addWidget(row_widget)
            animated_rows.append(row_widget)
        self.schedule_rows.addStretch()
        self.motion.reveal_staggered(animated_rows, 30)

    def _rebuild_recent_search(self, items: list[dict]) -> None:
        self._clear_layout(self.search_rows)
        if not items:
            label = QLabel("暂无最近索引内容")
            label.setProperty("muted", True)
            self.search_rows.addWidget(label)
            self.search_rows.addStretch()
            return
        animated_rows = []
        for item in items[:5]:
            row_widget = QWidget()
            row = QHBoxLayout(row_widget)
            row.setContentsMargins(0, 5, 0, 5)
            row.setSpacing(8)
            symbol = QLabel("◷")
            symbol.setProperty("muted", True)
            row.addWidget(symbol)
            text = QVBoxLayout()
            text.setSpacing(1)
            title = QLabel(str(item.get("title") or item.get("url") or "本地索引项"))
            title.setStyleSheet("font-weight: 610;")
            title.setWordWrap(False)
            meta = QLabel(f"{item.get('object_type', 'index')}  ·  本地索引")
            meta.setProperty("muted", True)
            meta.setStyleSheet("font-size: 10px;")
            text.addWidget(title)
            text.addWidget(meta)
            row.addLayout(text, 1)
            self.search_rows.addWidget(row_widget)
            animated_rows.append(row_widget)
        self.search_rows.addStretch()
        self.motion.reveal_staggered(animated_rows, 26)

    def _rebuild_stats(self, snapshot: dict, database_bytes: int) -> None:
        file_counts: Counter[str] = snapshot["file_counts"]
        roles = ("success", "info", "warning", "accent", "text_muted")
        labels = ("HTML", "PDF", "TXT", "JSON", "Other")
        values = [float(file_counts.get(label, 0)) for label in labels]
        total = sum(values)
        if total <= 0:
            values = [1, 0, 0, 0, 0]
            total = 1
        donut_items = [(label, value, role) for label, value, role in strict_zip(labels, values, roles, strict=True)]
        self.donut.set_items(donut_items, f"{int(sum(snapshot['file_counts'].values())):,} 项")

        self._clear_layout(self.file_legend)
        for label, value, role in donut_items:
            row = QHBoxLayout()
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {getattr(self.theme.current, role, self.theme.current.accent)};")
            name = QLabel(label)
            name.setProperty("muted", True)
            percent = QLabel(f"{value * 100 / total:.1f}%")
            percent.setProperty("muted", True)
            row.addWidget(dot)
            row.addWidget(name)
            row.addStretch()
            row.addWidget(percent)
            self.file_legend.addLayout(row)
        self.file_legend.addStretch()

        self._clear_layout(self.domain_rows)
        domains: list[tuple[str, int]] = snapshot["domains"]
        max_domain = max((count for _, count in domains), default=1)
        for domain, count in domains[:5]:
            self.domain_rows.addLayout(self._bar_row(domain, count, max_domain, f"{count:,}"))
        if not domains:
            empty = QLabel("暂无域名统计")
            empty.setProperty("muted", True)
            self.domain_rows.addWidget(empty)

        self._clear_layout(self.size_rows)
        type_values = list(strict_zip(labels, values, roles, strict=True))
        for label, value, _role in type_values:
            estimated = int(database_bytes * value / total) if database_bytes else 0
            self.size_rows.addLayout(self._size_row(label, estimated, value / total))
        if not database_bytes:
            note = QLabel("等待产生本地数据")
            note.setProperty("muted", True)
            self.size_rows.addWidget(note)

    def _bar_row(self, label: str, value: int, maximum: int, value_text: str) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(7)
        name = QLabel(label)
        name.setProperty("muted", True)
        name.setFixedWidth(90)
        progress = QProgressBar()
        progress.setRange(0, max(1, maximum))
        progress.setValue(0)
        progress.setTextVisible(False)
        progress.setFixedHeight(7)
        value_label = QLabel(value_text)
        value_label.setProperty("muted", True)
        value_label.setFixedWidth(52)
        value_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        row.addWidget(name)
        row.addWidget(progress, 1)
        row.addWidget(value_label)
        self.motion.animate_progress(progress, value, 340)
        return row

    def _size_row(self, label: str, size: int, share: float) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(7)
        name = QLabel(label)
        name.setProperty("muted", True)
        name.setFixedWidth(44)
        progress = QProgressBar()
        progress.setRange(0, 1000)
        target = round(max(0.0, min(1.0, share)) * 1000)
        progress.setValue(0)
        progress.setTextVisible(False)
        progress.setFixedHeight(7)
        value = QLabel(format_bytes(size))
        value.setProperty("muted", True)
        value.setFixedWidth(70)
        value.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        row.addWidget(name)
        row.addWidget(progress, 1)
        row.addWidget(value)
        self.motion.animate_progress(progress, target, 360)
        return row

    def _load_index_snapshot(self) -> dict:
        result: dict = {"file_counts": Counter(), "domains": [], "recent_items": []}
        try:
            with self.context.store.connect() as connection:
                urls = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT source_url FROM result_records ORDER BY fetched_at DESC LIMIT ?",
                        (800 if self.context.performance.mode == "efficiency" else 1500 if self.context.performance.mode == "balanced" else 2500,),
                    ).fetchall()
                    if row[0]
                ]
                recent = connection.execute(
                    "SELECT object_type,title,url FROM local_search ORDER BY rowid DESC LIMIT 5"
                ).fetchall()
            file_counts: Counter[str] = Counter(self._content_type(url) for url in urls)
            domains = Counter(urlparse(url).hostname or "local" for url in urls)
            result["file_counts"] = file_counts
            result["domains"] = domains.most_common(5)
            result["recent_items"] = [dict(row) for row in recent]
            self._index_snapshot_error_reported = False
        except sqlite3.Error:
                                                                                              
                                                                                            
                                                                                                 
            if not self._index_snapshot_error_reported:
                LOGGER.warning("Dashboard index snapshot unavailable; using empty snapshot", exc_info=True)
                self._index_snapshot_error_reported = True
        return result

    @staticmethod
    def _content_type(url: str) -> str:
        path = urlparse(url).path.casefold()
        if path.endswith(".pdf"):
            return "PDF"
        if path.endswith((".txt", ".md", ".csv")):
            return "TXT"
        if path.endswith((".json", ".jsonl")):
            return "JSON"
        if path.endswith((".html", ".htm", "/")) or "." not in path.rsplit("/", 1)[-1]:
            return "HTML"
        return "Other"

    @staticmethod
    def _run_url(snapshot: dict) -> str:
        requests = snapshot.get("requests", []) if isinstance(snapshot, dict) else []
        if requests and isinstance(requests[0], dict):
            return str(requests[0].get("url") or "")
        return ""

    @staticmethod
    def _run_speed(completed: int, started_at) -> float:
        if not started_at or completed <= 0:
            return 0.0
        try:
            start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
            now = datetime.now(start.tzinfo) if start.tzinfo else datetime.now()
            seconds = max(1.0, (now - start).total_seconds())
            return completed / seconds
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _format_datetime(value) -> str:
        if not value:
            return "暂无"
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return str(value)[:16]

    @staticmethod
    def _duration_text(run: dict) -> str:
        start_raw = run.get("started_at")
        end_raw = run.get("finished_at")
        if not start_raw or not end_raw:
            return "—"
        try:
            start = datetime.fromisoformat(str(start_raw).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(end_raw).replace("Z", "+00:00"))
            seconds = max(0, int((end - start).total_seconds()))
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        except ValueError:
            return "—"

    @staticmethod
    def _status_label(status: str, percent: int) -> str:
        mapping = {
            "running": f"运行中  {percent}%",
            "queued": "排队中",
            "paused": f"已暂停  {percent}%",
            "completed": "已完成",
            "partial": "部分完成",
            "failed": "失败",
            "cancelled": "已取消",
            "draft": "待执行",
        }
        return mapping.get(status.casefold(), status)

    @staticmethod
    def _schedule_text(schedule: dict) -> str:
        next_run = schedule.get("next_run_at")
        if next_run:
            return f"下次执行：{DashboardPage._format_datetime(next_run)}"
        rule = schedule.get("rule") or {}
        hour = int(rule.get("hour", 0) or 0)
        minute = int(rule.get("minute", 0) or 0)
        return f"计划执行：{hour:02d}:{minute:02d}"

    @staticmethod
    def _clear_layout(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            if item.layout():
                DashboardPage._clear_layout(item.layout())
