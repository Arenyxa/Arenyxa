from __future__ import annotations

import json
from typing import Any
from dataclasses import asdict

from arenyxa.qt_compat.QtCore import Qt
from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from arenyxa.application.extraction_studio import ExtractionDryRun, ExtractionField, ExtractionLivePicker, ExtractionStudioService
from arenyxa.application.extraction_runtime import ExtractionRecipeExecutor
from arenyxa.application.extraction_recipe import (
    ExtractionInteractionStep, ExtractionLoopSpec, ExtractionPaginationSpec, ExtractionRecipe, ExtractionRecipeCompiler,
)
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import NetworkEvent
from arenyxa.infrastructure.capture.replay import CapturedBodyResolver
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, set_table_header_stretch_last


class ExtractionStudioPage(WorkspacePage):
    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        self.service = ExtractionStudioService()
        self.dry_run = ExtractionDryRun()
        self.live_picker = ExtractionLivePicker()
        self._capture_ids: list[str] = []
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(
            PageHeader(
                "Extraction Lab",
                "No-code web extraction planning, API discovery, pagination analysis and workflow generation",
            ),
            1,
        )
        self.analyze_button = QPushButton("Analyze Capture")
        self.analyze_button.setProperty("primary", True)
        self.dry_run_button = QPushButton("Dry Run Local Body")
        self.pick_button = QPushButton("Pick from Page")
        header.addWidget(self.pick_button)
        header.addWidget(self.dry_run_button)
        header.addWidget(self.analyze_button)
        root.addLayout(header)

        source_row = QHBoxLayout()
        self.capture = QComboBox()
        self.capture.setMinimumWidth(280)
        self.refresh_button = QPushButton("Refresh Captures")
        self.source_url = QLineEdit()
        self.source_url.setPlaceholderText("Optional source URL; captured API/HTTP sources are auto-discovered")
        source_row.addWidget(QLabel("Capture"))
        source_row.addWidget(self.capture)
        source_row.addWidget(self.refresh_button)
        source_row.addWidget(QLabel("Source"))
        source_row.addWidget(self.source_url, 1)
        root.addLayout(source_row)

        splitter = QSplitter(Qt.Orientation.Vertical)
        field_holder = QWidget()
        field_layout = QVBoxLayout(field_holder)
        field_layout.setContentsMargins(0, 0, 0, 0)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Extraction Fields"))
        controls.addStretch()
        self.add_field_button = QPushButton("Add Field")
        self.remove_field_button = QPushButton("Remove Field")
        controls.addWidget(self.add_field_button)
        controls.addWidget(self.remove_field_button)
        field_layout.addLayout(controls)
        self.fields = QTableWidget(0, 6)
        self.fields.setHorizontalHeaderLabels(["Name", "Type", "Selector", "Attribute", "Required", "Multiple"])
        self.fields.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.fields.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        set_table_header_stretch_last(self.fields, True)
        field_layout.addWidget(self.fields, 1)
        splitter.addWidget(field_holder)

        self.output_tabs = QTabWidget()
        self.analysis_output = QPlainTextEdit()
        self.workflow_output = QPlainTextEdit()
        self.preview_output = QPlainTextEdit()
        self.picker_output = QPlainTextEdit()
        self.recipe_panel = self._build_recipe_panel()
        self.analysis_output.setReadOnly(True)
        self.workflow_output.setReadOnly(True)
        self.preview_output.setReadOnly(True)
        self.picker_output.setReadOnly(True)
        self.analysis_output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.workflow_output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.preview_output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.picker_output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.output_tabs.addTab(self.analysis_output, "Discovery & Plan")
        self.output_tabs.addTab(self.workflow_output, "Workflow Draft")
        self.output_tabs.addTab(self.preview_output, "Dry Run Preview")
        self.output_tabs.addTab(self.picker_output, "Element Picker")
        self.output_tabs.addTab(self.recipe_panel, "Recipe Builder")
        splitter.addWidget(self.output_tabs)
        splitter.setSizes([360, 520])
        root.addWidget(splitter, 1)

        safety = QLabel(
            "Extraction Lab analyzes local capture history and generates bounded workflow drafts. "
            "Actual network execution continues to use Arenyxa request, concurrency and network-governance policies."
        )
        safety.setWordWrap(True)
        safety.setProperty("muted", True)
        root.addWidget(safety)

        self.refresh_button.clicked.connect(self.refresh_captures)
        self.add_field_button.clicked.connect(self.add_field)
        self.remove_field_button.clicked.connect(self.remove_field)
        self.analyze_button.clicked.connect(self.analyze_capture)
        self.dry_run_button.clicked.connect(self.dry_run_capture)
        self.pick_button.clicked.connect(self.pick_from_page)
        self.add_field("title", "css", "title")

    def _build_recipe_panel(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        basics = QHBoxLayout()
        self.recipe_name = QLineEdit("Professional Web Extraction")
        self.recipe_name.setPlaceholderText("Recipe name")
        self.recipe_max_records = QSpinBox()
        self.recipe_max_records.setRange(1, 1_000_000)
        self.recipe_max_records.setValue(10_000)
        self.recipe_auth = QCheckBox("Authentication required")
        basics.addWidget(QLabel("Recipe"))
        basics.addWidget(self.recipe_name, 1)
        basics.addWidget(QLabel("Max records"))
        basics.addWidget(self.recipe_max_records)
        basics.addWidget(self.recipe_auth)
        layout.addLayout(basics)

        loop_row = QHBoxLayout()
        self.recipe_loop_selector = QLineEdit()
        self.recipe_loop_selector.setPlaceholderText("Optional collection selector, e.g. article.card")
        self.recipe_loop_limit = QSpinBox()
        self.recipe_loop_limit.setRange(1, 100000)
        self.recipe_loop_limit.setValue(1000)
        loop_row.addWidget(QLabel("Loop"))
        loop_row.addWidget(self.recipe_loop_selector, 1)
        loop_row.addWidget(QLabel("Items"))
        loop_row.addWidget(self.recipe_loop_limit)
        layout.addLayout(loop_row)

        page_row = QHBoxLayout()
        self.recipe_pagination_mode = QComboBox()
        self.recipe_pagination_mode.addItems(["none", "next_button", "page_parameter", "cursor", "infinite_scroll"])
        self.recipe_pagination_target = QLineEdit()
        self.recipe_pagination_target.setPlaceholderText("Next selector or parameter name")
        self.recipe_cursor_selector = QLineEdit()
        self.recipe_cursor_selector.setPlaceholderText("Cursor selector (cursor mode), e.g. [data-next-cursor]")
        self.recipe_cursor_attribute = QLineEdit()
        self.recipe_cursor_attribute.setPlaceholderText("Optional cursor attribute; blank = text")
        self.recipe_max_pages = QSpinBox()
        self.recipe_max_pages.setRange(1, 10000)
        self.recipe_max_pages.setValue(100)
        page_row.addWidget(QLabel("Pagination"))
        page_row.addWidget(self.recipe_pagination_mode)
        page_row.addWidget(self.recipe_pagination_target, 1)
        page_row.addWidget(QLabel("Max pages"))
        page_row.addWidget(self.recipe_max_pages)
        layout.addLayout(page_row)
        cursor_row = QHBoxLayout()
        cursor_row.addWidget(QLabel("Cursor"))
        cursor_row.addWidget(self.recipe_cursor_selector, 2)
        cursor_row.addWidget(self.recipe_cursor_attribute, 1)
        layout.addLayout(cursor_row)

        step_header = QHBoxLayout()
        step_header.addWidget(QLabel("Interaction Steps"))
        step_header.addStretch()
        self.recipe_add_step = QPushButton("Add Step")
        self.recipe_remove_step = QPushButton("Remove Step")
        step_header.addWidget(self.recipe_add_step)
        step_header.addWidget(self.recipe_remove_step)
        layout.addLayout(step_header)
        self.recipe_steps = QTableWidget(0, 6)
        self.recipe_steps.setHorizontalHeaderLabels(["ID", "Kind", "Selector", "Value", "Timeout ms", "Optional"])
        self.recipe_steps.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.recipe_steps.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        set_table_header_stretch_last(self.recipe_steps, True)
        layout.addWidget(self.recipe_steps, 1)
        self.recipe_add_step.clicked.connect(self._add_recipe_step)
        self.recipe_remove_step.clicked.connect(self._remove_recipe_step)
        buttons = QHBoxLayout()
        self.recipe_validate = QPushButton("Validate Recipe")
        self.recipe_compile = QPushButton("Compile Flow Draft")
        self.recipe_run = QPushButton("Run Browser Recipe")
        self.recipe_run.setProperty("primary", True)
        buttons.addWidget(self.recipe_validate)
        buttons.addWidget(self.recipe_compile)
        buttons.addWidget(self.recipe_run)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.recipe_output = QPlainTextEdit()
        self.recipe_output.setReadOnly(True)
        self.recipe_output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        layout.addWidget(self.recipe_output, 1)
        self.recipe_validate.clicked.connect(lambda: self._compile_recipe(False))
        self.recipe_compile.clicked.connect(lambda: self._compile_recipe(True))
        self.recipe_run.clicked.connect(self._run_recipe)
        return holder

    def _add_recipe_step(self, kind: str = "click") -> None:
        row = self.recipe_steps.rowCount()
        self.recipe_steps.insertRow(row)
        self.recipe_steps.setItem(row, 0, QTableWidgetItem(f"step-{row + 1}"))
        kind_box = QComboBox()
        kind_box.addItems(["wait", "click", "double_click", "hover", "focus", "input", "press", "select", "check", "uncheck", "scroll", "condition"])
        index = kind_box.findText(kind)
        if index >= 0:
            kind_box.setCurrentIndex(index)
        self.recipe_steps.setCellWidget(row, 1, kind_box)
        self.recipe_steps.setItem(row, 2, QTableWidgetItem(""))
        self.recipe_steps.setItem(row, 3, QTableWidgetItem(""))
        timeout = QSpinBox()
        timeout.setRange(250, 120000)
        timeout.setValue(10000)
        optional = QCheckBox()
        self.recipe_steps.setCellWidget(row, 4, timeout)
        self.recipe_steps.setCellWidget(row, 5, optional)
        self.recipe_steps.setCurrentCell(row, 0)

    def _remove_recipe_step(self) -> None:
        row = self.recipe_steps.currentRow()
        if row >= 0:
            self.recipe_steps.removeRow(row)

    def _recipe(self) -> ExtractionRecipe:
        steps: list[ExtractionInteractionStep] = []
        for row in range(self.recipe_steps.rowCount()):
            id_item = self.recipe_steps.item(row, 0)
            selector_item = self.recipe_steps.item(row, 2)
            value_item = self.recipe_steps.item(row, 3)
            kind_box = self.recipe_steps.cellWidget(row, 1)
            timeout_box = self.recipe_steps.cellWidget(row, 4)
            optional_box = self.recipe_steps.cellWidget(row, 5)
            step_id = id_item.text().strip() if id_item is not None else ""
            selector = selector_item.text().strip() if selector_item is not None else ""
            value = value_item.text() if value_item is not None else ""
            kind = kind_box.currentText() if isinstance(kind_box, QComboBox) else "click"
            timeout_ms = timeout_box.value() if isinstance(timeout_box, QSpinBox) else 10000
            optional = optional_box.isChecked() if isinstance(optional_box, QCheckBox) else False
            if step_id:
                steps.append(ExtractionInteractionStep(step_id, kind, selector, value, timeout_ms, optional))
        loop_selector = self.recipe_loop_selector.text().strip()
        loop = ExtractionLoopSpec(loop_selector, self.recipe_loop_limit.value()) if loop_selector else None
        mode = self.recipe_pagination_mode.currentText().strip().casefold()
        target = self.recipe_pagination_target.text().strip()
        pagination = None
        if mode != "none":
            pagination = ExtractionPaginationSpec(
                mode=mode,
                selector=target if mode in {"next_button", "infinite_scroll"} else "",
                parameter=target if mode in {"page_parameter", "cursor"} else "",
                cursor_selector=self.recipe_cursor_selector.text().strip() if mode == "cursor" else "",
                cursor_attribute=self.recipe_cursor_attribute.text().strip() if mode == "cursor" else "",
                maximum_pages=self.recipe_max_pages.value(),
            )
        return ExtractionRecipe(
            name=self.recipe_name.text().strip(),
            source_url=self.source_url.text().strip(),
            fields=self._fields(),
            steps=steps,
            loop=loop,
            pagination=pagination,
            authentication_required=self.recipe_auth.isChecked(),
            max_records=self.recipe_max_records.value(),
        )

    def _run_recipe(self) -> None:
        try:
            recipe = self._recipe()
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            QMessageBox.warning(self, "Extraction Recipe", str(exc))
            return
        self.recipe_run.setEnabled(False)
        self.recipe_output.setPlainText("Running bounded browser extraction…")
        vault = getattr(getattr(self.context, "nextgen", None), "vault", None)
        resolver = getattr(vault, "get", None) if vault is not None else None
        def execute_recipe() -> dict[str, Any]:
            return ExtractionRecipeExecutor().execute(
                recipe, headless=True, secret_resolver=resolver if callable(resolver) else None
            ).snapshot()
        def completed(value: object) -> None:
            self.recipe_run.setEnabled(True)
            self.recipe_output.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit("Extraction browser recipe completed")
        def failed(message: str) -> None:
            self.recipe_run.setEnabled(True)
            self.recipe_output.setPlainText(message)
            QMessageBox.warning(self, "Extraction Recipe", message)
        run_background(execute_recipe, completed, failed)

    def _compile_recipe(self, compile_flow: bool) -> None:
        try:
            recipe = self._recipe()
            compiler = ExtractionRecipeCompiler()
            warnings = compiler.validate(recipe)
            payload = {"recipe": recipe.snapshot(), "warnings": warnings}
            if compile_flow:
                payload["workflow"] = compiler.compile(recipe)
            self.recipe_output.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit("Extraction runtime flow draft compiled" if compile_flow else "Extraction recipe validated")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            QMessageBox.warning(self, "Extraction Recipe", str(exc))

    def activated(self) -> None:
        self.refresh_captures()

    def refresh_captures(self) -> None:
        current = self._selected_capture_id()
        rows = self.context.store.list_captures(200)
        self.capture.clear()
        self._capture_ids = []
        selected_index = -1
        for row in rows:
            session_id = str(row.get("id") or "")
            if not session_id:
                continue
            label = f"{str(row.get('created_at') or '')[:19]} · {str(row.get('source_type') or 'capture')} · {int(row.get('event_count') or 0):,} events"
            self._capture_ids.append(session_id)
            self.capture.addItem(label)
            if session_id == current:
                selected_index = len(self._capture_ids) - 1
        if selected_index >= 0:
            self.capture.setCurrentIndex(selected_index)
        elif not self._capture_ids:
            self.capture.addItem("No capture sessions available")

    def _selected_capture_id(self) -> str:
        index = self.capture.currentIndex()
        if 0 <= index < len(self._capture_ids):
            return self._capture_ids[index]
        return ""

    def add_field(self, name: str = "field", selector_type: str = "css", selector: str = "") -> None:
        row = self.fields.rowCount()
        self.fields.insertRow(row)
        self.fields.setItem(row, 0, QTableWidgetItem(name))
        type_box = QComboBox()
        type_box.addItems(["css", "xpath", "jsonpath", "text", "aria", "attribute"])
        index = type_box.findText(selector_type)
        if index >= 0:
            type_box.setCurrentIndex(index)
        self.fields.setCellWidget(row, 1, type_box)
        self.fields.setItem(row, 2, QTableWidgetItem(selector))
        self.fields.setItem(row, 3, QTableWidgetItem(""))
        required = QCheckBox()
        multiple = QCheckBox()
        self.fields.setCellWidget(row, 4, required)
        self.fields.setCellWidget(row, 5, multiple)
        self.fields.setCurrentCell(row, 0)

    def remove_field(self) -> None:
        row = self.fields.currentRow()
        if row >= 0:
            self.fields.removeRow(row)

    def _fields(self) -> list[ExtractionField]:
        result: list[ExtractionField] = []
        for row in range(self.fields.rowCount()):
            name_item = self.fields.item(row, 0)
            selector_item = self.fields.item(row, 2)
            attribute_item = self.fields.item(row, 3)
            type_box = self.fields.cellWidget(row, 1)
            required_box = self.fields.cellWidget(row, 4)
            multiple_box = self.fields.cellWidget(row, 5)
            name = name_item.text().strip() if name_item is not None else ""
            selector = selector_item.text().strip() if selector_item is not None else ""
            attribute = attribute_item.text().strip() if attribute_item is not None else ""
            selector_type = type_box.currentText() if isinstance(type_box, QComboBox) else "css"
            required = required_box.isChecked() if isinstance(required_box, QCheckBox) else False
            multiple = multiple_box.isChecked() if isinstance(multiple_box, QCheckBox) else False
            if not name and not selector:
                continue
            result.append(ExtractionField(name, selector_type, selector, attribute, required, multiple))
        return result

    def _events(self, session_id: str) -> list[NetworkEvent]:
        events: list[NetworkEvent] = []
        for row in self.context.store.iter_network_events(session_id, self.service.MAX_EVENTS):
            normalized = dict(row)
            try:
                normalized["source_type"] = CaptureSource(str(normalized.get("source_type") or CaptureSource.BROWSER.value))
                payload = {key: value for key, value in normalized.items() if key in NetworkEvent.__dataclass_fields__}
                events.append(NetworkEvent(**payload))
            except (TypeError, ValueError):
                continue
        return events


    def pick_from_page(self) -> None:
        url = self.source_url.text().strip()
        if not url:
            QMessageBox.information(self, "Extraction Lab", "Enter the page URL you want to inspect first.")
            return
        self.pick_button.setEnabled(False)
        self.statusMessage.emit("Extraction Picker opened · click one element in the browser window")

        def work() -> object:
            return self.live_picker.pick(url, timeout_seconds=180, headless=False)

        def completed(value: object) -> None:
            self.pick_button.setEnabled(True)
            result = value
            suggested = result.suggested_field
            self.add_field(suggested.name, suggested.selector_type, suggested.selector)
            row = self.fields.currentRow()
            if row >= 0:
                attribute_item = self.fields.item(row, 3)
                if attribute_item is not None:
                    attribute_item.setText(suggested.attribute)
                multiple_box = self.fields.cellWidget(row, 5)
                if isinstance(multiple_box, QCheckBox):
                    multiple_box.setChecked(bool(suggested.multiple))
            self.picker_output.setPlainText(json.dumps(asdict(result), ensure_ascii=False, indent=2, default=str))
            self.output_tabs.setCurrentWidget(self.picker_output)
            self.statusMessage.emit(f"Extraction Picker selected {result.tag} · {suggested.selector_type}:{suggested.selector}")

        def failed(message: str) -> None:
            self.pick_button.setEnabled(True)
            QMessageBox.warning(self, "Extraction Picker", message)

        run_background(work, completed, failed)

    def dry_run_capture(self) -> None:
        session_id = self._selected_capture_id()
        if not session_id:
            QMessageBox.information(self, "Extraction Lab", "Select a capture session with stored response bodies first.")
            return
        fields = self._fields()
        if not fields:
            QMessageBox.information(self, "Extraction Lab", "Add at least one extraction field first.")
            return
        self.dry_run_button.setEnabled(False)

        def work() -> object:
            events = self._events(session_id)
            resolver = CapturedBodyResolver(self.context.store, self.context.paths.captures)
            return self.dry_run.preview(events, fields, lambda ref, limit: resolver.load_for_schema(ref, limit))

        def completed(value: object) -> None:
            self.dry_run_button.setEnabled(True)
            result = value
            self.preview_output.setPlainText(json.dumps(asdict(result), ensure_ascii=False, indent=2, default=str))
            self.output_tabs.setCurrentWidget(self.preview_output)
            self.statusMessage.emit("Extraction Lab local dry run completed")

        def failed(message: str) -> None:
            self.dry_run_button.setEnabled(True)
            QMessageBox.warning(self, "Extraction Lab", message)

        run_background(work, completed, failed)

    def analyze_capture(self) -> None:
        session_id = self._selected_capture_id()
        source_url = self.source_url.text().strip()
        fields = self._fields()
        if not session_id and not source_url:
            QMessageBox.information(self, "Extraction Lab", "Select a capture session or enter a source URL first.")
            return
        self.analyze_button.setEnabled(False)

        def work() -> object:
            events = self._events(session_id) if session_id else []
            return self.service.analyze(events, source_url=source_url, fields=fields)

        def completed(value: object) -> None:
            self.analyze_button.setEnabled(True)
            result = value
            payload = asdict(result)
            workflow = payload.pop("workflow_draft", {})
            self.analysis_output.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            self.workflow_output.setPlainText(json.dumps(workflow, ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit("Extraction Lab analysis completed")

        def failed(message: str) -> None:
            self.analyze_button.setEnabled(True)
            QMessageBox.warning(self, "Extraction Lab", message)

        run_background(work, completed, failed)
