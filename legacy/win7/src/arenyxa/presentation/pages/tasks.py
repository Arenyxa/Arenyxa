from __future__ import annotations

import json

from arenyxa.qt_compat.QtCore import Signal
from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from arenyxa.domain.enums import TaskStatus
from arenyxa.application.reliability import PreflightRequest
from arenyxa.domain.models import CleanerStep, FieldSpec, RequestSpec, Task
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, set_table_header_resize_mode


class TaskEditor(QDialog):
    def __init__(self, task: Task | None = None, parent=None) -> None:
        super().__init__(parent)
        self.task = task
        self.setWindowTitle("编辑采集任务" if task else "新建采集任务")
        self.resize(760, 620)
        layout = QVBoxLayout(self)
        tabs = QTabWidget()
        layout.addWidget(tabs, 1)

        request_tab = QWidget()
        request_form = QFormLayout(request_tab)
        self.name = QLineEdit(task.name if task else "")
        self.url = QTextEdit()
        self.url.setMaximumHeight(110)
        self.url.setPlaceholderText("每行一个 URL；多个 URL 将按并发策略同时抓取")
        existing_urls = [request.url for request in task.requests] if task and task.requests else ["https://example.com"]
        self.url.setPlainText("\n".join(existing_urls))
        self.method = QComboBox()
        self.method.addItems(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
        if task and task.requests:
            self.method.setCurrentText(task.requests[0].method)
        self.headers = QTextEdit()
        self.headers.setPlaceholderText('{"Accept": "text/html"}')
        self.headers.setPlainText(
            json.dumps(
                task.requests[0].headers if task and task.requests else {}, ensure_ascii=False, indent=2
            )
        )
        self.body = QTextEdit(task.requests[0].body or "" if task and task.requests else "")
        self.parser = QComboBox()
        self.parser.addItems(["auto", "html", "json", "xml"])
        if task:
            self.parser.setCurrentText(task.parser_hint)
        request_form.addRow("任务名称", self.name)
        request_form.addRow("目标 URL（每行一个）", self.url)
        request_form.addRow("HTTP 方法", self.method)
        request_form.addRow("Headers (JSON)", self.headers)
        request_form.addRow("请求正文", self.body)
        request_form.addRow("解析类型", self.parser)
        tabs.addTab(request_tab, "请求")

        fields_tab = QWidget()
        fields_layout = QVBoxLayout(fields_tab)
        self.fields = QTableWidget(0, 7)
        self.fields.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.fields.setHorizontalHeaderLabels(["名称", "选择器", "类型", "目标", "属性", "多值", "必填"])
        set_table_header_resize_mode(self.fields, 1, QHeaderView.ResizeMode.Stretch)
        fields_layout.addWidget(self.fields)
        buttons = QHBoxLayout()
        add = QPushButton("添加字段")
        remove = QPushButton("删除字段")
        buttons.addWidget(add)
        buttons.addWidget(remove)
        buttons.addStretch()
        fields_layout.addLayout(buttons)
        add.clicked.connect(self._add_field)
        remove.clicked.connect(
            lambda: self.fields.removeRow(self.fields.currentRow()) if self.fields.currentRow() >= 0 else None
        )
        tabs.addTab(fields_tab, "字段抽取")
        for spec in task.fields if task else [FieldSpec("title", "title", cleaners=[CleanerStep("trim")])]:
            self._add_field(spec)

        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet("color: #ff6570;")
        layout.addWidget(self.error)
        controls = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        controls.accepted.connect(self._validate_accept)
        controls.rejected.connect(self.reject)
        layout.addWidget(controls)

    def _add_field(self, spec: FieldSpec | None = None) -> None:
        row = self.fields.rowCount()
        self.fields.insertRow(row)
        values = [
            spec.name if spec else f"field_{row + 1}",
            spec.selector if spec else "",
            spec.selector_type if spec else "css",
            spec.target if spec else "text",
            spec.attribute or "" if spec else "",
            "1" if spec and spec.multiple else "0",
            "1" if spec and spec.required else "0",
        ]
        for column, value in enumerate(values):
            self.fields.setItem(row, column, QTableWidgetItem(value))

    def _validate_accept(self) -> None:
        try:
            headers = json.loads(self.headers.toPlainText() or "{}")
            if not isinstance(headers, dict):
                raise TypeError("Headers 必须是 JSON 对象。")
            task = self.build_task(headers)
            errors = task.validate()
            if errors:
                raise ValueError("\n".join(errors))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            self.error.setText(str(exc))
            return
        self.accept()

    def build_task(self, headers: dict[str, str] | None = None) -> Task:
        if headers is None:
            headers = json.loads(self.headers.toPlainText() or "{}")
        fields = []
        for row in range(self.fields.rowCount()):

            def value(column: int, row: int = row) -> str:
                item = self.fields.item(row, column)
                return item.text().strip() if item else ""

            fields.append(
                FieldSpec(
                    name=value(0),
                    selector=value(1),
                    selector_type=value(2) or "css",
                    target=value(3) or "text",
                    attribute=value(4) or None,
                    multiple=value(5) in {"1", "true", "yes"},
                    required=value(6) in {"1", "true", "yes"},
                    cleaners=[CleanerStep("trim"), CleanerStep("normalize_whitespace")],
                )
            )
        urls: list[str] = []
        seen_urls: set[str] = set()
        for raw_url in self.url.toPlainText().splitlines():
            url = raw_url.strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            urls.append(url)
        requests = [
            RequestSpec(
                url=url,
                method=self.method.currentText(),
                headers=dict(headers),
                body=self.body.toPlainText() or None,
                content_type=headers.get("Content-Type"),
            )
            for url in urls
        ]
        if self.task:
            return Task(
                name=self.name.text().strip(),
                requests=requests,
                fields=fields,
                id=self.task.id,
                status=self.task.status,
                tags=self.task.tags,
                parser_hint=self.parser.currentText(),
                created_at=self.task.created_at,
                schema_version=self.task.schema_version,
            )
        return Task(
            name=self.name.text().strip(),
            requests=requests,
            fields=fields,
            parser_hint=self.parser.currentText(),
        )


class TasksPage(WorkspacePage):
    runProgress = Signal(object)

    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        toolbar = QHBoxLayout()
        toolbar.addWidget(PageHeader("抓取任务", "Task 定义与 Run 事实分离，历史运行保留配置快照"), 1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索名称、标签或 URL")
        self.search.setMaximumWidth(320)
        create = QPushButton("新建任务")
        create.setProperty("primary", True)
        toolbar.addWidget(self.search)
        toolbar.addWidget(create)
        layout.addLayout(toolbar)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["任务", "URL", "状态", "字段", "更新时间", "操作"])
        set_table_header_resize_mode(self.table, 0, QHeaderView.ResizeMode.ResizeToContents)
        set_table_header_resize_mode(self.table, 1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 1)
        create.clicked.connect(self.create_task)
        self.search.textChanged.connect(self.refresh)
        self.table.cellDoubleClicked.connect(lambda row, _column: self.edit_task(row))
        self.runProgress.connect(self._show_run_progress)

    def activated(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        tasks = self.context.store.list_tasks(query=self.search.text().strip(), limit=500)
        self.table.setRowCount(len(tasks))
        self._tasks = tasks
        for row, task in enumerate(tasks):
            values = [
                task.name,
                (
                    task.requests[0].url + (f"  (+{len(task.requests) - 1})" if len(task.requests) > 1 else "")
                    if task.requests else ""
                ),
                task.status.value,
                str(len(task.fields)),
                task.updated_at[:19],
            ]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))
            actions = QWidget()
            buttons = QHBoxLayout(actions)
            buttons.setContentsMargins(2, 2, 2, 2)
            buttons.setSpacing(4)
            run = QPushButton("运行")
            preview = QPushButton("预览")
            edit = QPushButton("编辑")
            buttons.addWidget(run)
            buttons.addWidget(preview)
            buttons.addWidget(edit)
            run.clicked.connect(lambda _checked=False, task=task: self.run_task(task, False))
            preview.clicked.connect(lambda _checked=False, task=task: self.run_task(task, True))
            edit.clicked.connect(lambda _checked=False, task=task: self.open_editor(task))
            self.table.setCellWidget(row, 5, actions)
        self.inspectorChanged.emit("任务列表", {"count": len(tasks), "query": self.search.text()})

    def create_task(self) -> None:
        self.open_editor(None)

    def edit_task(self, row: int) -> None:
        if 0 <= row < len(self._tasks):
            self.open_editor(self._tasks[row])

    def open_editor(self, task: Task | None) -> None:
        editor = TaskEditor(task, self)
        if editor.exec() == QDialog.DialogCode.Accepted:
            saved = editor.build_task()
            saved.status = TaskStatus.READY
            self.context.store.save_task(saved)
            self.statusMessage.emit(f"已保存任务：{saved.name}")
            self.refresh()

    def run_task(self, task: Task, preview: bool) -> None:
        try:
            preflight = None
            if self.context.preflight is not None:
                resource_sample = None
                if self.context.resource_probe is not None:
                    try:
                        resource_sample = self.context.resource_probe.sample(
                            active_browser_instances=0 if self.context.browser_pool is None else self.context.browser_pool.active_count(),
                            active_workers=int(self.context.runner.concurrency_snapshot().get("active_requests", 0)),
                        )
                    except Exception:
                        resource_sample = None
                preflight = self.context.preflight.estimate(
                    PreflightRequest(
                        target_count=len(task.requests),
                        average_response_bytes=min(self.context.settings.max_response_bytes, 512 * 1024),
                        request_concurrency=self.context.settings.request_concurrency,
                    ),
                    resource_snapshot=resource_sample,
                )
                if not preview and preflight.risk_level == "high":
                    risks = ", ".join(preflight.risks) or "capacity"
                    choice = QMessageBox.warning(
                        self,
                        "执行前资源评估",
                        f"该任务被评估为高资源风险（{risks}）。预计磁盘上界约 {preflight.estimated_disk_bytes_high / (1024**3):.2f} GiB，"
                        f"峰值 RAM 约 {preflight.estimated_peak_ram_bytes / (1024**3):.2f} GiB。继续运行？",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                    )
                    if choice != QMessageBox.StandardButton.Yes:
                        self.statusMessage.emit("已根据执行前资源评估取消启动；任务定义未修改。")
                        return
            handle = self.context.runner.submit(task, self._run_progress, preview=preview)
            concurrency = self.context.runner.concurrency_snapshot()
            self.statusMessage.emit(
                f"已{'预览' if preview else '启动'}：{task.name} · {len(task.requests)} URL · "
                f"并发预算 {concurrency.get('request_limit', concurrency['request_workers'])}/{concurrency['request_workers']} / 单域名 {concurrency['per_host_workers']} · {handle.run.id}"
                + ("" if preflight is None else f" · Preflight {preflight.risk_level}")
            )
            self.context.nextgen.activity.publish("run", f"Started {task.name}", details={"run_id": handle.run.id, "task_id": task.id, "preview": preview})
            handle.future.add_done_callback(lambda _future, run=handle.run, name=task.name: self.context.nextgen.activity.publish("run-complete", f"{name}: {run.status.value}", level="error" if run.status.value == "failed" else "info", details={"run_id": run.id, "success": run.success_count, "failure": run.failure_count}))
        except Exception as exc:                                          
            QMessageBox.critical(self, "无法启动", str(exc))

    def _run_progress(self, run) -> None:
        self.runProgress.emit(run)

    def _show_run_progress(self, run) -> None:
        self.statusMessage.emit(
            f"{run.stage} · {run.completed_units}/{run.total_units or '?'} · {run.status.value}"
        )
