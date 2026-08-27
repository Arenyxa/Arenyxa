from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from arenyxa.qt_compat.QtCore import QTimer
from arenyxa.qt_compat.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from arenyxa import __version__
from arenyxa.application.nextgen import (
    BrowserAction, DistributedWorker, RequestAssertion,
    SelectorFingerprint, WorkflowDebugger,
)
from arenyxa.application.runtime_ecosystem import BrowserProfile
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import NetworkEvent, RequestSpec, RetryPolicy, Workflow, WorkflowNode
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader


class IntelligenceStudioPage(WorkspacePage):
    





    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        self._debugger = WorkflowDebugger()
        self._last_selector_fingerprint: dict[str, Any] | None = None
        self._last_response = None
        self._last_smartpath: dict[str, Any] | None = None
        self._last_blueprint: dict[str, Any] | None = None
        self._last_portable_workflow: Workflow | None = None
        self._last_autopilot_response = None
        self._last_autopilot_events: list[NetworkEvent] = []
        self._last_autopilot_plan: dict[str, Any] | None = None
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("Arenyxa Intelligence Studio", "Explainable Blueprint · SmartPath 2.0 · Context Bridge · Selector Self-Healing · Compatibility Lab · Portable Workflows · Debugger"), 1)
        self.refresh_live_button = QPushButton("Refresh Live Center")
        header.addWidget(self.refresh_live_button)
        layout.addLayout(header)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        self._build_smartpath_tab()
        self._build_blueprint_tab()
        self._build_selector_tab()
        self._build_http_tab()
        self._build_protocol_tab()
        self._build_quality_tab()
        self._build_recorder_tab()
        self._build_debugger_tab()
        self._build_secrets_tab()
        self._build_templates_environment_tab()
        self._build_ecosystem_tab()
        self._build_workers_tab()
        self._build_compatibility_tab()
        self._build_portability_tab()
        self._build_live_tab()
        self._build_autopilot_tab()

        self.refresh_live_button.clicked.connect(self.refresh_live)
        self.live_timer = QTimer(self)
        self.live_timer.timeout.connect(self.refresh_live)
        self.live_timer.setInterval(max(500, int(context.performance.status_refresh_ms)))

                                   
    @staticmethod
    def _editor(readonly: bool = False, text: str = "") -> QPlainTextEdit:
        editor = QPlainTextEdit()
        editor.setReadOnly(readonly)
        if text:
            editor.setPlainText(text)
        return editor

    @staticmethod
    def _json(editor: QPlainTextEdit, fallback: Any) -> Any:
        text = editor.toPlainText().strip()
        if not text:
            return fallback
        return json.loads(text)

    def _capture_events(self, session_id: str | None = None, limit: int = 20_000) -> list[NetworkEvent]:
        if not session_id:
            captures = self.context.store.list_captures(limit=1)
            session_id = captures[0]["id"] if captures else None
        if not session_id:
            return []
        events = []
        for raw in self.context.store.iter_network_events(session_id, limit=limit):
            normalized = dict(raw)
            normalized["source_type"] = CaptureSource(normalized["source_type"])
            normalized["sensitivity_flags"] = normalized.pop("sensitivity", [])
            events.append(NetworkEvent(**{key: value for key, value in normalized.items() if key in NetworkEvent.__dataclass_fields__}))
        return events

    def _async(self, fn, output: QPlainTextEdit, success_message: str = "完成") -> None:
        output.setPlainText("Working…")
        def completed(value: object) -> None:
            if isinstance(value, str):
                output.setPlainText(value)
            else:
                output.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit(success_message)
        def failed(message: str) -> None:
            output.setPlainText(message)
            self.statusMessage.emit("操作失败")
        run_background(fn, completed, failed)

                                               
    def _build_smartpath_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.smart_url = QLineEdit("https://example.com")
        self.smart_url.setPlaceholderText("授权分析 URL")
        self.smart_session = QComboBox(); self.smart_session.setMinimumWidth(260)
        self.smart_analyze = QPushButton("Analyze SmartPath 2.0"); self.smart_analyze.setProperty("primary", True)
        self.smart_bridge = QPushButton("Top API → HTTP Builder")
        self.smart_workflow = QPushButton("Top API → Workflow")
        row.addWidget(QLabel("URL")); row.addWidget(self.smart_url, 1); row.addWidget(QLabel("Capture")); row.addWidget(self.smart_session); row.addWidget(self.smart_analyze); row.addWidget(self.smart_bridge); row.addWidget(self.smart_workflow)
        self.smart_output = self._editor(True)
        layout.addLayout(row); layout.addWidget(self.smart_output, 1)
        self.tabs.addTab(tab, "SmartPath & Data Sources")
        self.smart_analyze.clicked.connect(self.run_smartpath)
        self.smart_bridge.clicked.connect(self.bridge_top_api_to_http)
        self.smart_workflow.clicked.connect(self.bridge_top_api_to_workflow)

    def run_smartpath(self) -> None:
        url = self.smart_url.text().strip(); session = self.smart_session.currentData()
        def worker():
            response = self.context.nextgen.request.send(RequestSpec(url)) if url else None
            events = self._capture_events(session)
            result = self.context.nextgen.web_intelligence.analyze(response, events)
            self._last_response = response
            payload = asdict(result)
            if response is not None:
                entry = self.context.nextgen.time_machine.record(
                    url=response.final_url or url, response=response, workflow=result.workflow, metadata={"source": "web-intelligence-center"}
                )
                payload["time_machine_entry"] = asdict(entry)
            self._last_smartpath = payload
            self.context.nextgen.activity.publish("web-intelligence", f"Web Intelligence analyzed {url or 'capture'}", details={"engine": result.recommended_engine, "confidence": result.confidence})
            return self._last_smartpath
        self._async(worker, self.smart_output, "Analyze SmartPath 2.0完成")

    def bridge_top_api_to_http(self) -> None:
        try:
            events = self._capture_events(self.smart_session.currentData())
            preferred = None
            if self._last_smartpath:
                sources = self._last_smartpath.get("data_sources", [])
                for source in sources:
                    if source.get("kind") in {"xhr-json", "graphql", "api-json"}:
                        location = str(source.get("location", ""))
                        preferred = next((event for event in events if event.url == location), None)
                        if preferred is not None:
                            break
            if preferred is None:
                preferred = next((event for event in events if event.url and ("/api/" in event.url or "graphql" in event.url.casefold())), None)
            if preferred is None:
                raise ValueError("当前 Capture 中没有找到可转换的 API 请求。")
            candidate = self.context.nextgen.web_intelligence.classify_endpoint(preferred)
            spec = self.context.nextgen.context_bridge.event_to_request(preferred, include_sensitive=False)
            if candidate is not None:
                spec.url = candidate.url
            self.http_method.setCurrentText(spec.method)
            self.http_url.setText(spec.url)
            self.http_headers.setPlainText(json.dumps(spec.headers, ensure_ascii=False, indent=2))
            self.http_query.setPlainText(json.dumps(spec.query, ensure_ascii=False, indent=2))
            self.http_cookies.setPlainText("{}")
            self.tabs.setCurrentIndex(3)
            self.statusMessage.emit("已将捕获 API 安全转换到 HTTP Builder；敏感 query/header/cookie 不会复制原值。")
        except Exception as exc:
            QMessageBox.warning(self, "Context Bridge", str(exc))

    def bridge_top_api_to_workflow(self) -> None:
        try:
            events = self._capture_events(self.smart_session.currentData())
            candidates = self.context.nextgen.web_intelligence.replay_candidates(events)
            safe = next((item for item in candidates if item.safe_to_replay), None)
            if safe is None:
                raise ValueError("当前 Capture 没有可自动转换的安全幂等 API；敏感或非幂等请求必须人工审查。")
            preferred = next((event for event in events if event.id == safe.event_id), None)
            if preferred is None:
                raise ValueError("Capture 候选已失效，请刷新捕获会话。")
            workflow = self.context.nextgen.web_intelligence.event_to_workflow(preferred, require_safe=True)
            self.smart_output.setPlainText(json.dumps(asdict(workflow), ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit("安全 API 已转换为 Workflow；敏感材料未复制，非幂等请求不会自动转换。")
        except Exception as exc:
            QMessageBox.warning(self, "Web Intelligence → Workflow", str(exc))

                                                                  
    def _build_blueprint_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.blueprint_url = QLineEdit("https://example.com")
        self.blueprint_url.setPlaceholderText("授权分析 URL")
        self.blueprint_session = QComboBox(); self.blueprint_session.setMinimumWidth(260)
        self.blueprint_run = QPushButton("Analyze → Explain → Blueprint"); self.blueprint_run.setProperty("primary", True)
        self.blueprint_to_debugger = QPushButton("Workflow → Debugger")
        row.addWidget(QLabel("URL")); row.addWidget(self.blueprint_url, 1); row.addWidget(QLabel("Capture")); row.addWidget(self.blueprint_session); row.addWidget(self.blueprint_run); row.addWidget(self.blueprint_to_debugger)
        self.blueprint_output = self._editor(True)
        layout.addLayout(row); layout.addWidget(QLabel("Explainable decision trace · engine cost/stability estimates · fallback chain · starter workflow")); layout.addWidget(self.blueprint_output, 1)
        self.tabs.addTab(tab, "Explainable Blueprint")
        self.blueprint_run.clicked.connect(self.run_blueprint)
        self.blueprint_to_debugger.clicked.connect(self.blueprint_workflow_to_debugger)

    def run_blueprint(self) -> None:
        url = self.blueprint_url.text().strip(); session = self.blueprint_session.currentData()
        def worker():
            response = self.context.nextgen.request.send(RequestSpec(url)) if url else self._last_response
            events = self._capture_events(session)
            blueprint = self.context.nextgen.intelligence.analyze(response, events)
            payload = asdict(blueprint)
            self._last_blueprint = payload
            self.context.nextgen.activity.publish("intelligence-blueprint", f"Blueprint analyzed {url or 'capture'}", details={"engine": blueprint.recommended_engine, "confidence": blueprint.confidence, "risks": len(blueprint.risk_flags)})
            return payload
        self._async(worker, self.blueprint_output, "Explainable Blueprint 分析完成")

    def blueprint_workflow_to_debugger(self) -> None:
        if not self._last_blueprint:
            QMessageBox.information(self, "Explainable Blueprint", "请先生成 Blueprint。")
            return
        workflow = self._last_blueprint.get("workflow")
        if not isinstance(workflow, dict):
            return
        compact = {"name": workflow.get("name", "Blueprint Workflow"), "id": workflow.get("id", "blueprint"), "nodes": workflow.get("nodes", [])}
        self.debug_workflow.setPlainText(json.dumps(compact, ensure_ascii=False, indent=2))
        self.tabs.setCurrentWidget(self.tabs.widget(7))
        self.statusMessage.emit("Blueprint Workflow 已发送到 Workflow Debugger。")

                                    
    def _build_selector_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.selector_type = QComboBox(); self.selector_type.addItems(["css", "xpath"])
        self.selector_value = QLineEdit("title")
        self.selector_analyze = QPushButton("Analyze / Generate Candidates")
        self.selector_heal = QPushButton("Self-Heal")
        row.addWidget(self.selector_type); row.addWidget(self.selector_value, 1); row.addWidget(self.selector_analyze); row.addWidget(self.selector_heal)
        self.selector_html = self._editor(False, "<html><head><title>Arenyxa</title></head><body><button data-testid='submit'>Run</button></body></html>")
        self.selector_output = self._editor(True)
        layout.addLayout(row); layout.addWidget(QLabel("HTML / DOM Snapshot")); layout.addWidget(self.selector_html, 1); layout.addWidget(QLabel("Results")); layout.addWidget(self.selector_output, 1)
        self.tabs.addTab(tab, "Selector Studio")
        self.selector_analyze.clicked.connect(self.run_selector)
        self.selector_heal.clicked.connect(self.heal_selector)

    def run_selector(self) -> None:
        try:
            result = self.context.nextgen.selector.analyze(self.selector_html.toPlainText(), self.selector_value.text().strip(), self.selector_type.currentText())
            self._last_selector_fingerprint = result.get("fingerprint")
            self.selector_output.setPlainText(json.dumps(result, ensure_ascii=False, indent=2))
            self.context.nextgen.activity.publish("selector", "Selector analyzed", details={"matches": result.get("matches", 0)})
        except Exception as exc:
            QMessageBox.warning(self, "Selector Studio", str(exc))

    def heal_selector(self) -> None:
        if not self._last_selector_fingerprint:
            QMessageBox.information(self, "Selector Studio", "请先在旧 DOM 上执行一次分析以保存元素指纹。")
            return
        try:
            result = [asdict(item) for item in self.context.nextgen.selector.heal(self.selector_html.toPlainText(), SelectorFingerprint(**self._last_selector_fingerprint))]
            self.selector_output.setPlainText(json.dumps(result, ensure_ascii=False, indent=2))
            self.context.nextgen.activity.publish("selector-heal", "Selector self-heal completed", details={"candidates": len(result)})
        except Exception as exc:
            QMessageBox.warning(self, "Selector Self-Heal", str(exc))

                                
    def _build_http_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.http_method = QComboBox(); self.http_method.addItems(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        self.http_url = QLineEdit("https://example.com")
        self.http_send = QPushButton("Send + Assertions"); self.http_send.setProperty("primary", True)
        self.http_target = QComboBox(); self.http_target.addItems(["curl", "python", "httpx", "fetch", "axios", "powershell", "playwright"])
        self.http_generate = QPushButton("Generate Code")
        self.http_workflow = QPushButton("Request → Workflow")
        row.addWidget(self.http_method); row.addWidget(self.http_url, 1); row.addWidget(self.http_send); row.addWidget(self.http_target); row.addWidget(self.http_generate); row.addWidget(self.http_workflow)

        details = QTabWidget()
        self.http_headers = self._editor(False, '{\n  "Accept": "*/*"\n}')
        self.http_query = self._editor(False, '{}')
        self.http_cookies = self._editor(False, '{}')
        self.http_body = self._editor(False, "")
        self.http_options = self._editor(False, f'{{\n  "content_type": null,\n  "connect_timeout": 10,\n  "read_timeout": 30,\n  "verify_tls": true,\n  "proxy": null,\n  "user_agent": "Arenyxa/{__version__}",\n  "retry_attempts": 2\n}}')
        self.http_variables = self._editor(False, '{\n  "base_url": "https://example.com"\n}')
        self.http_actions = self._editor(False, '[\n  {"action":"set_header","name":"X-Arenyxa-Test","value":"1"}\n]')
        self.http_assertions = self._editor(False, '[\n  {"kind":"status_between","expected":[200,399]}\n]')
        for label, editor in (("Headers", self.http_headers), ("Query", self.http_query), ("Cookies", self.http_cookies), ("Body", self.http_body), ("Options", self.http_options), ("Variables", self.http_variables), ("Pre-request Actions", self.http_actions), ("Assertions", self.http_assertions)):
            page = QWidget(); page_layout_ = QVBoxLayout(page); page_layout_.addWidget(editor); details.addTab(page, label)
        self.http_output = self._editor(True)
        layout.addLayout(row); layout.addWidget(details, 1); layout.addWidget(self.http_output, 1)
        self.tabs.addTab(tab, "HTTP Request Builder")
        self.http_send.clicked.connect(self.send_http)
        self.http_generate.clicked.connect(self.generate_http_code)
        self.http_workflow.clicked.connect(self.http_to_workflow)

    def _request_spec(self) -> RequestSpec:
        headers = self._json(self.http_headers, {}); query = self._json(self.http_query, {}); cookies = self._json(self.http_cookies, {})
        options = self._json(self.http_options, {})
        retry = RetryPolicy(attempts=max(0, min(10, int(options.get("retry_attempts", 2)))))
        spec = RequestSpec(
            url=self.http_url.text().strip(), method=self.http_method.currentText(),
            query={str(k): str(v) for k, v in dict(query).items()}, headers={str(k): str(v) for k, v in dict(headers).items()},
            cookies={str(k): str(v) for k, v in dict(cookies).items()}, body=self.http_body.toPlainText() or None,
            content_type=options.get("content_type"), connect_timeout=float(options.get("connect_timeout", 10)),
            read_timeout=float(options.get("read_timeout", 30)), verify_tls=bool(options.get("verify_tls", True)),
            proxy=options.get("proxy"), user_agent=str(options.get("user_agent") or f"Arenyxa/{__version__}"), retry=retry,
        )
        variables = self._json(self.http_variables, {})
        if variables: spec = self.context.nextgen.request.apply_variables(spec, variables)
        actions = self._json(self.http_actions, [])
        if actions: spec = self.context.nextgen.request.apply_actions(spec, actions)
        return spec

    def send_http(self) -> None:
        try:
            spec = self._request_spec(); assertions = [RequestAssertion(**item) for item in self._json(self.http_assertions, [])]
        except Exception as exc:
            QMessageBox.warning(self, "HTTP Request Builder", str(exc)); return
        def worker():
            checked = self.context.nextgen.request.send_with_assertions(spec, assertions)
            response = checked["response"]; self._last_response = response
            self.context.nextgen.activity.publish("http", f"{spec.method} {spec.url}", level="info" if checked["passed"] else "warning", details={"status": response.status, "elapsed_ms": response.elapsed_ms, "assertions_passed": checked["passed"]})
            return {"status": response.status, "final_url": response.final_url, "elapsed_ms": round(response.elapsed_ms, 2), "headers": response.headers, "assertions": checked["assertions"], "assertions_passed": checked["passed"], "body_preview": response.body.decode(response.encoding, errors="replace")[:100_000]}
        self._async(worker, self.http_output, "HTTP 请求完成")

    def generate_http_code(self) -> None:
        try:
            self.http_output.setPlainText(self.context.nextgen.request.generator.generate(self._request_spec(), self.http_target.currentText()))
        except Exception as exc:
            QMessageBox.warning(self, "Code Generator", str(exc))

    def http_to_workflow(self) -> None:
        try:
            workflow = self.context.nextgen.context_bridge.request_to_workflow(self._request_spec(), name="HTTP Builder Workflow")
            document = self.context.nextgen.portability.dumps(workflow)
            self.portable_output.setPlainText(document)
            self.tabs.setCurrentIndex(14)
            self.context.nextgen.activity.publish("context-bridge", "HTTP Request converted to portable Workflow", details={"schema":"arenyxa.workflow/v1"})
            self.statusMessage.emit("HTTP Request 已转换为可审阅 Portable Workflow。")
        except Exception as exc:
            QMessageBox.warning(self, "Context Bridge", str(exc))

                                    
    def _build_protocol_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        row = QHBoxLayout(); self.protocol_session = QComboBox(); self.protocol_analyze = QPushButton("Analyze GraphQL / WebSocket / SSE")
        row.addWidget(self.protocol_session, 1); row.addWidget(self.protocol_analyze)
        self.protocol_output = self._editor(True)
        layout.addLayout(row); layout.addWidget(self.protocol_output, 1)
        self.tabs.addTab(tab, "Protocol Inspector")
        self.protocol_analyze.clicked.connect(self.run_protocols)

    def run_protocols(self) -> None:
        session = self.protocol_session.currentData()
        def worker():
            events = self._capture_events(session)
            return {"graphql": self.context.nextgen.protocols.graphql(events), "websocket": self.context.nextgen.protocols.websocket(events), "sse": self.context.nextgen.protocols.sse(events)}
        self._async(worker, self.protocol_output, "协议分析完成")

                                   
    def _build_quality_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        self.quality_input = self._editor(False, '[\n  {"name":"A","price":10},\n  {"name":"B","price":12},\n  {"name":"B","price":12}\n]')
        row=QHBoxLayout(); button = QPushButton("Analyze Quality & Schema"); self.quality_clean=QPushButton("Clean / Deduplicate")
        self.quality_rules=QLineEdit('{"defaults":{},"type_coercions":{},"trim_strings":true,"deduplicate":true}'); self.quality_rules.setPlaceholderText("Cleaning rules JSON")
        row.addWidget(button); row.addWidget(self.quality_clean); row.addWidget(self.quality_rules,1)
        self.quality_output = self._editor(True)
        layout.addWidget(self.quality_input, 1); layout.addLayout(row); layout.addWidget(self.quality_output, 1)
        self.tabs.addTab(tab, "Data Quality Studio")
        button.clicked.connect(self.run_quality); self.quality_clean.clicked.connect(self.clean_quality)

    def run_quality(self) -> None:
        try:
            records = self._json(self.quality_input, [])
            if not isinstance(records, list) or any(not isinstance(item, dict) for item in records): raise ValueError("输入必须是 JSON object 数组。")
            result = self.context.nextgen.quality.analyze(records)
            self.quality_output.setPlainText(json.dumps(result, ensure_ascii=False, indent=2))
            self.context.nextgen.activity.publish("quality", "Data quality analyzed", details={"records": len(records), "score": result["quality_score"]})
        except Exception as exc:
            QMessageBox.warning(self, "Data Quality Studio", str(exc))

    def clean_quality(self) -> None:
        try:
            records=self._json(self.quality_input,[]); rules=json.loads(self.quality_rules.text() or "{}")
            result=self.context.nextgen.quality.clean(records,deduplicate=bool(rules.get("deduplicate",True)),defaults=rules.get("defaults",{}),type_coercions=rules.get("type_coercions",{}),trim_strings=bool(rules.get("trim_strings",True)))
            self.quality_input.setPlainText(json.dumps(result["records"],ensure_ascii=False,indent=2)); self.quality_output.setPlainText(json.dumps({k:v for k,v in result.items() if k!="records"},ensure_ascii=False,indent=2))
            self.context.nextgen.activity.publish("quality-clean","Data cleaned",details={"input":result["input_count"],"output":result["output_count"],"changes":result["changes"]})
        except Exception as exc: QMessageBox.warning(self,"Data Quality Studio",str(exc))

                                    
    def _build_recorder_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        self.recorder_input = self._editor(False, '[\n  {"kind":"goto","url":"https://example.com"},\n  {"kind":"click","selector":"button[data-testid=submit]"}\n]')
        row = QHBoxLayout(); self.recorder_lang = QComboBox(); self.recorder_lang.addItems(["python", "javascript"]); self.recorder_generate = QPushButton("Generate Workflow + Playwright")
        self.recorder_run = QPushButton("Run Headless")
        self.recorder_live_url = QLineEdit("https://example.com"); self.recorder_live_url.setMinimumWidth(220)
        self.recorder_live_seconds = QSpinBox(); self.recorder_live_seconds.setRange(5, 900); self.recorder_live_seconds.setValue(30); self.recorder_live_seconds.setSuffix(" s")
        self.recorder_live = QPushButton("Record Live Browser")
        row.addWidget(self.recorder_lang); row.addWidget(self.recorder_generate); row.addWidget(self.recorder_run); row.addWidget(self.recorder_live_url); row.addWidget(self.recorder_live_seconds); row.addWidget(self.recorder_live); row.addStretch()
        self.recorder_output = self._editor(True)
        layout.addWidget(QLabel("Recorder events JSON")); layout.addWidget(self.recorder_input, 1); layout.addLayout(row); layout.addWidget(self.recorder_output, 1)
        self.tabs.addTab(tab, "Browser Recorder 2.0")
        self.recorder_generate.clicked.connect(self.run_recorder)
        self.recorder_run.clicked.connect(self.execute_recording)
        self.recorder_live.clicked.connect(self.record_live_browser)

    def run_recorder(self) -> None:
        try:
            actions = [BrowserAction(**item) for item in self._json(self.recorder_input, [])]
            workflow = self.context.nextgen.recorder.to_workflow(actions)
            code = self.context.nextgen.recorder.to_playwright(actions, self.recorder_lang.currentText())
            self.recorder_output.setPlainText(json.dumps({"workflow": asdict(workflow), "playwright": code}, ensure_ascii=False, indent=2))
            self.context.nextgen.activity.publish("recorder", "Browser recording converted", details={"actions": len(actions)})
        except Exception as exc:
            QMessageBox.warning(self, "Browser Recorder", str(exc))

    def execute_recording(self) -> None:
        try:
            actions = [BrowserAction(**item) for item in self._json(self.recorder_input, [])]
        except Exception as exc:
            QMessageBox.warning(self, "Browser Recorder", str(exc)); return
        def worker():
            events = self.context.nextgen.recorder.execute_playwright(actions, headless=True)
            self.context.nextgen.activity.publish("recorder-run", "Browser recording executed", details={"actions": len(actions)})
            return events
        self._async(worker, self.recorder_output, "Browser Recorder 执行完成")

    def record_live_browser(self) -> None:
        url = self.recorder_live_url.text().strip(); seconds = self.recorder_live_seconds.value()
        self.recorder_output.setPlainText("Starting interactive Chromium recorder… Password values are never captured.")
        def worker():
            actions = self.context.nextgen.recorder.record_live(url, duration_seconds=seconds, headless=False)
            self.context.nextgen.activity.publish("recorder-live", "Interactive browser recording completed", details={"actions": len(actions), "duration_seconds": seconds})
            return [asdict(item) for item in actions]
        def completed(value: object) -> None:
            self.recorder_input.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, default=str))
            self.recorder_output.setPlainText(f"Recorded {len(value) if isinstance(value, list) else 0} actions. You can now generate Workflow / Playwright code.")
            self.statusMessage.emit("Browser Recorder 实时录制完成")
        def failed(message: str) -> None:
            self.recorder_output.setPlainText(message); self.statusMessage.emit("实时录制失败")
        run_background(worker, completed, failed)

                                    
    def _build_debugger_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        default_workflow = {"name":"Debug Pipeline","nodes":[{"id":"source","kind":"source","config":{},"next_ids":["validate"]},{"id":"validate","kind":"validate","config":{"required":["title"]},"next_ids":["sink"],"failure_ids":[]},{"id":"sink","kind":"sink","config":{},"next_ids":[]}]}
        self.debug_workflow = self._editor(False, json.dumps(default_workflow, ensure_ascii=False, indent=2))
        self.debug_inputs = self._editor(False, '[{"title":"Arenyxa"},{"title":""}]')
        self.debug_scopes = self._editor(False, '{"project":{"base_url":"https://example.com"},"workflow":{"page":1},"run":{"timestamp":"preview"}}')
        row = QHBoxLayout(); self.debug_breakpoints = QLineEdit("validate"); self.debug_prepare = QPushButton("Prepare"); self.debug_step = QPushButton("Step"); self.debug_continue = QPushButton("Continue"); self.debug_resolve = QPushButton("Resolve Variables")
        row.addWidget(QLabel("Breakpoints")); row.addWidget(self.debug_breakpoints, 1); row.addWidget(self.debug_prepare); row.addWidget(self.debug_step); row.addWidget(self.debug_continue); row.addWidget(self.debug_resolve)
        self.debug_output = self._editor(True)
        layout.addWidget(self.debug_workflow, 1); layout.addWidget(QLabel("Inputs")); layout.addWidget(self.debug_inputs); layout.addWidget(QLabel("Variable scopes (secret.* resolves via Secrets Vault)")); layout.addWidget(self.debug_scopes); layout.addLayout(row); layout.addWidget(self.debug_output, 1)
        self.tabs.addTab(tab, "Workflow Debugger")
        self.debug_prepare.clicked.connect(self.prepare_debugger); self.debug_step.clicked.connect(self.step_debugger); self.debug_continue.clicked.connect(self.continue_debugger); self.debug_resolve.clicked.connect(self.resolve_debug_variables)

    def _workflow_from_json(self) -> Workflow:
        raw = self._json(self.debug_workflow, {})
        if hasattr(self, "debug_scopes"):
            raw = self.context.nextgen.variables.resolve(raw, self._json(self.debug_scopes, {}), self.context.nextgen.vault.get)
        return Workflow(name=raw.get("name", "Debug Workflow"), id=raw.get("id", "debug-workflow"), nodes=[WorkflowNode(**item) for item in raw.get("nodes", [])])

    def prepare_debugger(self) -> None:
        try:
            snapshot = self._debugger.prepare(self._workflow_from_json(), self._json(self.debug_inputs, []), [item.strip() for item in self.debug_breakpoints.text().split(",") if item.strip()])
            self.debug_output.setPlainText(json.dumps(asdict(snapshot), ensure_ascii=False, indent=2))
        except Exception as exc: QMessageBox.warning(self, "Workflow Debugger", str(exc))

    def resolve_debug_variables(self) -> None:
        try:
            raw=self._json(self.debug_workflow,{})
            scopes=self._json(self.debug_scopes,{})
            resolved=self.context.nextgen.variables.resolve(raw,scopes,self.context.nextgen.vault.get)
            self.debug_output.setPlainText(json.dumps(resolved,ensure_ascii=False,indent=2))
        except Exception as exc: QMessageBox.warning(self,"Workflow Variables",str(exc))

    def step_debugger(self) -> None:
        try: self.debug_output.setPlainText(json.dumps(asdict(self._debugger.step(ignore_breakpoint=True)), ensure_ascii=False, indent=2))
        except Exception as exc: QMessageBox.warning(self, "Workflow Debugger", str(exc))

    def continue_debugger(self) -> None:
        try: self.debug_output.setPlainText(json.dumps(asdict(self._debugger.continue_run()), ensure_ascii=False, indent=2))
        except Exception as exc: QMessageBox.warning(self, "Workflow Debugger", str(exc))

                                   
    def _build_secrets_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        form = QFormLayout(); self.secret_name = QLineEdit(); self.secret_value = QLineEdit(); self.secret_value.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Name", self.secret_name); form.addRow("Value", self.secret_value)
        row = QHBoxLayout(); save = QPushButton("Save / Update"); delete = QPushButton("Delete"); reveal = QPushButton("Reveal once"); refresh = QPushButton("Refresh names")
        for button in (save, delete, reveal, refresh): row.addWidget(button)
        row.addStretch(); self.secret_output = self._editor(True)
        layout.addLayout(form); layout.addLayout(row); layout.addWidget(self.secret_output, 1)
        self.tabs.addTab(tab, "Secrets Vault")
        save.clicked.connect(self.save_secret); delete.clicked.connect(self.delete_secret); reveal.clicked.connect(self.reveal_secret); refresh.clicked.connect(self.refresh_secrets)

    def save_secret(self) -> None:
        try:
            self.context.nextgen.vault.set(self.secret_name.text(), self.secret_value.text()); self.secret_value.clear(); self.refresh_secrets(); self.context.nextgen.activity.publish("secret", "Secret updated", details={"name": self.secret_name.text()})
        except Exception as exc: QMessageBox.warning(self, "Secrets Vault", str(exc))

    def delete_secret(self) -> None:
        try: self.context.nextgen.vault.delete(self.secret_name.text()); self.refresh_secrets()
        except Exception as exc: QMessageBox.warning(self, "Secrets Vault", str(exc))

    def reveal_secret(self) -> None:
        try:
            value = self.context.nextgen.vault.get(self.secret_name.text())
            self.secret_output.setPlainText("(not found)" if value is None else value)
            QTimer.singleShot(10_000, lambda: self.secret_output.clear())
        except Exception as exc: QMessageBox.warning(self, "Secrets Vault", str(exc))

    def refresh_secrets(self) -> None:
        self.secret_output.setPlainText("\n".join(self.context.nextgen.vault.names()) or "(empty)")

                                                   
    def _build_templates_environment_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        row = QHBoxLayout(); self.template_box = QComboBox(); self.template_box.addItems(self.context.nextgen.templates.templates().keys()); show = QPushButton("Preview Template"); create_template=QPushButton("Create in Project")
        row.addWidget(self.template_box, 1); row.addWidget(show); row.addWidget(create_template)
        form = QFormLayout(); self.project_name = QLineEdit("MyProject"); self.project_env = self._editor(False, '{\n  "BASE_URL": "https://example.com"\n}')
        form.addRow("Project", self.project_name)
        actions = QHBoxLayout(); ensure = QPushButton("Create / Ensure Project Env"); save = QPushButton("Save Environment"); load = QPushButton("Load Environment")
        self.py_status = QPushButton("Python Env Status"); self.py_create = QPushButton("Create .venv"); self.py_freeze = QPushButton("pip freeze")
        self.py_packages = QLineEdit(); self.py_packages.setPlaceholderText("可选：requests httpx pandas")
        self.py_install = QPushButton("Install Packages")
        for button in (ensure, save, load, self.py_status, self.py_create, self.py_freeze): actions.addWidget(button)
        self.template_output = self._editor(True)
        package_row = QHBoxLayout(); package_row.addWidget(QLabel("Project Python")); package_row.addWidget(self.py_packages, 1); package_row.addWidget(self.py_install)
        layout.addLayout(row); layout.addWidget(self.project_env); layout.addLayout(actions); layout.addLayout(package_row); layout.addWidget(self.template_output, 1)
        self.tabs.addTab(tab, "Templates & Project Environment")
        show.clicked.connect(lambda: self.template_output.setPlainText(json.dumps(self.context.nextgen.templates.templates()[self.template_box.currentText()], ensure_ascii=False, indent=2)))
        create_template.clicked.connect(self.create_template_in_project)
        ensure.clicked.connect(self.ensure_project); save.clicked.connect(self.save_project_env); load.clicked.connect(self.load_project_env)
        self.py_status.clicked.connect(self.python_env_status); self.py_create.clicked.connect(self.create_python_env); self.py_freeze.clicked.connect(self.freeze_python_env); self.py_install.clicked.connect(self.install_python_packages)

    def create_template_in_project(self) -> None:
        try:
            project=self.context.nextgen.projects.ensure(self.project_name.text()); template_id=self.template_box.currentText(); template=self.context.nextgen.templates.templates()[template_id]
            path=Path(project["workflows"]) / f"{template_id}.template.json"; atomic_write_json(path, template)
            self.template_output.setPlainText(str(path)); self.context.nextgen.activity.publish("template","Workflow template created",details={"template":template_id,"project":self.project_name.text()})
        except Exception as exc: QMessageBox.warning(self,"Workflow Template",str(exc))

    def ensure_project(self) -> None:
        try: self.template_output.setPlainText(json.dumps(self.context.nextgen.projects.ensure(self.project_name.text()), ensure_ascii=False, indent=2))
        except Exception as exc: QMessageBox.warning(self, "Project Environment", str(exc))
    def save_project_env(self) -> None:
        try:
            path = self.context.nextgen.projects.save_environment(self.project_name.text(), self._json(self.project_env, {})); self.template_output.setPlainText(str(path))
        except Exception as exc: QMessageBox.warning(self, "Project Environment", str(exc))
    def load_project_env(self) -> None:
        try: self.project_env.setPlainText(json.dumps(self.context.nextgen.projects.load_environment(self.project_name.text()), ensure_ascii=False, indent=2))
        except Exception as exc: QMessageBox.warning(self, "Project Environment", str(exc))

    def python_env_status(self) -> None:
        try: self.template_output.setPlainText(json.dumps(self.context.nextgen.python_envs.status(self.project_name.text()), ensure_ascii=False, indent=2))
        except Exception as exc: QMessageBox.warning(self, "Project Python", str(exc))

    def create_python_env(self) -> None:
        project = self.project_name.text()
        self._async(lambda: self.context.nextgen.python_envs.create(project), self.template_output, "项目 Python 环境已创建")

    def freeze_python_env(self) -> None:
        project = self.project_name.text()
        self._async(lambda: self.context.nextgen.python_envs.freeze(project), self.template_output, "pip freeze 完成")

    def install_python_packages(self) -> None:
        project = self.project_name.text(); packages = [item for item in self.py_packages.text().split() if item]
        if not packages:
            QMessageBox.information(self, "Project Python", "请输入至少一个包名。")
            return
        if QMessageBox.question(self, "安装 Python 包", "这会从配置的 Python 包索引下载并执行第三方安装包。是否继续？") != QMessageBox.StandardButton.Yes:
            return
        self._async(lambda: self.context.nextgen.python_envs.install(project, packages), self.template_output, "Python 包安装完成")

                                                                     
    def _build_ecosystem_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        profile_form = QFormLayout()
        self.profile_id = QLineEdit("default"); self.profile_name = QLineEdit("Default Browser Profile")
        self.profile_ua = QLineEdit(f"Arenyxa/{__version__}"); self.profile_locale = QLineEdit("zh-CN"); self.profile_timezone = QLineEdit("Asia/Shanghai"); self.profile_proxy = QLineEdit()
        self.profile_secrets = QLineEdit(); self.profile_secrets.setPlaceholderText("JSON，例如 {\"cookie\":\"site.cookie\"}")
        for label, widget in (("Profile ID", self.profile_id), ("Name", self.profile_name), ("User-Agent", self.profile_ua), ("Locale", self.profile_locale), ("Timezone", self.profile_timezone), ("Proxy", self.profile_proxy), ("Secret refs", self.profile_secrets)):
            profile_form.addRow(label, widget)
        profile_actions = QHBoxLayout(); psave=QPushButton("Save Profile"); pload=QPushButton("Load Profile"); pexport=QPushButton("Export Safe Metadata")
        for button in (psave,pload,pexport): profile_actions.addWidget(button)
        marketplace = QHBoxLayout(); self.market_source=QLineEdit(); self.market_source.setPlaceholderText("本地 catalog.json 或 HTTPS catalog URL"); self.market_load=QPushButton("Load Marketplace"); self.market_item=QComboBox(); self.market_install=QPushButton("Install Selected")
        marketplace.addWidget(self.market_source,1); marketplace.addWidget(self.market_load); marketplace.addWidget(self.market_item,1); marketplace.addWidget(self.market_install)
        self.ecosystem_output=self._editor(True)
        layout.addWidget(QLabel("Browser Profile Manager")); layout.addLayout(profile_form); layout.addLayout(profile_actions); layout.addWidget(QLabel("Workflow Marketplace (optional, checksum-verified)")); layout.addLayout(marketplace); layout.addWidget(self.ecosystem_output,1)
        self.tabs.addTab(tab,"Profiles & Marketplace")
        psave.clicked.connect(self.save_browser_profile); pload.clicked.connect(self.load_browser_profile); pexport.clicked.connect(self.export_browser_profile)
        self.market_load.clicked.connect(self.load_marketplace); self.market_install.clicked.connect(self.install_marketplace_item)
        self._market_items=[]

    def save_browser_profile(self) -> None:
        try:
            refs=json.loads(self.profile_secrets.text() or "{}")
            profile=BrowserProfile(id=self.profile_id.text().strip(), name=self.profile_name.text().strip(), user_agent=self.profile_ua.text(), locale=self.profile_locale.text(), timezone=self.profile_timezone.text(), proxy=self.profile_proxy.text().strip() or None, secret_refs={str(k):str(v) for k,v in dict(refs).items()})
            path=self.context.nextgen.browser_profiles.save(profile); self.ecosystem_output.setPlainText(str(path)); self.context.nextgen.activity.publish("browser-profile","Browser profile saved",details={"id":profile.id})
        except Exception as exc: QMessageBox.warning(self,"Browser Profile",str(exc))

    def load_browser_profile(self) -> None:
        try:
            profile=self.context.nextgen.browser_profiles.load(self.profile_id.text().strip()); self.profile_name.setText(profile.name); self.profile_ua.setText(profile.user_agent); self.profile_locale.setText(profile.locale); self.profile_timezone.setText(profile.timezone); self.profile_proxy.setText(profile.proxy or ""); self.profile_secrets.setText(json.dumps(profile.secret_refs,ensure_ascii=False)); self.ecosystem_output.setPlainText(json.dumps(asdict(profile),ensure_ascii=False,indent=2))
        except Exception as exc: QMessageBox.warning(self,"Browser Profile",str(exc))

    def export_browser_profile(self) -> None:
        try:
            destination=self.context.nextgen.projects.path(self.project_name.text()) / "browser-profile" / f"{self.profile_id.text().strip()}.json"
            path=self.context.nextgen.browser_profiles.export_metadata(self.profile_id.text().strip(),destination); self.ecosystem_output.setPlainText(str(path))
        except Exception as exc: QMessageBox.warning(self,"Browser Profile",str(exc))

    def load_marketplace(self) -> None:
        source=self.market_source.text().strip()
        if not source: QMessageBox.information(self,"Marketplace","请输入本地 catalog 路径或 HTTPS URL。"); return
        def worker(): return self.context.nextgen.marketplace.load_catalog(Path(source) if "://" not in source else source)
        def completed(value: object) -> None:
            self._market_items=list(value); self.market_item.clear()
            for item in self._market_items: self.market_item.addItem(f"{item.name} · {item.version}",item.id)
            self.ecosystem_output.setPlainText(json.dumps([asdict(item) for item in self._market_items],ensure_ascii=False,indent=2)); self.context.nextgen.activity.publish("marketplace","Marketplace catalog loaded",details={"items":len(self._market_items)})
        run_background(worker,completed,lambda message:self.ecosystem_output.setPlainText(message))

    def install_marketplace_item(self) -> None:
        index=self.market_item.currentIndex()
        if index < 0 or index >= len(self._market_items): return
        item=self._market_items[index]
        if QMessageBox.question(self,"Install Workflow Package",f"安装 {item.name} {item.version}？\n权限声明：{', '.join(item.permissions) or 'none'}") != QMessageBox.StandardButton.Yes: return
        destination=self.context.nextgen.projects.path(self.project_name.text()) / "workflows" / f"{item.id}-{item.version}.arenyxa-workflow"
        self._async(lambda:self.context.nextgen.marketplace.install(item,destination),self.ecosystem_output,"Workflow package installed")

                                               
    def _build_workers_tab(self) -> None:
        tab=QWidget(); layout=QVBoxLayout(tab); form=QFormLayout()
        self.worker_id=QLineEdit("worker-1"); self.worker_name=QLineEdit("Arenyxa Worker 1"); self.worker_url=QLineEdit("http://127.0.0.1:8787"); self.worker_secret=QLineEdit("worker.worker-1.token"); self.worker_token=QLineEdit(); self.worker_token.setEchoMode(QLineEdit.EchoMode.Password); self.worker_weight=QSpinBox(); self.worker_weight.setRange(1,100); self.worker_weight.setValue(1)
        for label,widget in (("Worker ID",self.worker_id),("Name",self.worker_name),("Base URL",self.worker_url),("Token secret",self.worker_secret),("Token (optional update)",self.worker_token),("Weight",self.worker_weight)): form.addRow(label,widget)
        row=QHBoxLayout(); register=QPushButton("Register / Update"); health=QPushButton("Health"); tasks=QPushButton("Remote Tasks"); runs=QPushButton("Remote Runs"); remote_task=QLineEdit(); remote_task.setPlaceholderText("remote task id"); launch=QPushButton("Run Remote Task"); partition=QPushButton("Preview Partition")
        for widget in (register,health,tasks,runs,remote_task,launch,partition): row.addWidget(widget)
        self.worker_output=self._editor(True); layout.addLayout(form); layout.addLayout(row); layout.addWidget(self.worker_output,1); self.tabs.addTab(tab,"Distributed Workers")
        register.clicked.connect(self.register_worker); health.clicked.connect(lambda:self.worker_action("health")); tasks.clicked.connect(lambda:self.worker_action("tasks")); runs.clicked.connect(lambda:self.worker_action("runs")); launch.clicked.connect(lambda:self.worker_action("run",remote_task.text().strip())); partition.clicked.connect(lambda:self.worker_action("partition"))

    def register_worker(self) -> None:
        try:
            worker=DistributedWorker(self.worker_id.text().strip(),self.worker_name.text().strip(),self.worker_url.text().strip(),self.worker_secret.text().strip(),True,self.worker_weight.value()); token=self.worker_token.text() or None
            self.context.nextgen.workers.upsert(worker,token); self.worker_token.clear(); self.worker_output.setPlainText(json.dumps([asdict(item) for item in self.context.nextgen.workers.list()],ensure_ascii=False,indent=2)); self.context.nextgen.activity.publish("worker","Worker registered",details={"id":worker.id,"url":worker.base_url})
        except Exception as exc: QMessageBox.warning(self,"Distributed Worker",str(exc))

    def worker_action(self, action: str, value: str="") -> None:
        wid=self.worker_id.text().strip()
        def worker():
            if action=="health": return self.context.nextgen.workers.health(wid)
            if action=="tasks": return self.context.nextgen.workers.remote_tasks(wid)
            if action=="runs": return self.context.nextgen.workers.remote_runs(wid)
            if action=="run": return self.context.nextgen.workers.run_task(wid,value)
            if action=="partition": return self.context.nextgen.workers.partition(list(range(1,101)))
            return {}
        self._async(worker,self.worker_output,f"Worker {action} 完成")

                                             
    def _build_compatibility_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.compat_run = QPushButton("Run Offline Compatibility Baseline"); self.compat_run.setProperty("primary", True)
        self.compat_note = QLabel("Deterministic fixtures only · suitable for CI regression; not a live-web compatibility claim.")
        self.compat_note.setWordWrap(True)
        row.addWidget(self.compat_run); row.addWidget(self.compat_note, 1)
        self.compat_output = self._editor(True)
        layout.addLayout(row); layout.addWidget(self.compat_output, 1)
        self.tabs.addTab(tab, "Compatibility Lab")
        self.compat_run.clicked.connect(self.run_compatibility_lab)

    def run_compatibility_lab(self) -> None:
        total = len(self.context.nextgen.compatibility.default_cases())
        self.operationProgress.emit("Compatibility Lab", 0, total, "normal")
        self.compat_output.setPlainText("Running deterministic compatibility fixtures…")
        def worker():
            def progress(done: int, count: int, case_id: str) -> None:
                self.operationProgress.emit(f"Compatibility · {case_id}", done, count, "normal")
            return self.context.nextgen.compatibility.run(progress=progress)
        def completed(value: object) -> None:
            self.compat_output.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, default=str))
            self.operationProgress.emit("Compatibility Lab", total, total, "clear")
            payload = value if isinstance(value, dict) else {}
            self.context.nextgen.activity.publish("compatibility", "Offline compatibility baseline completed", details={"pass_rate": payload.get("pass_rate"), "cases": payload.get("cases")})
            self.statusMessage.emit("Compatibility Lab 回归完成")
        def failed(message: str) -> None:
            self.compat_output.setPlainText(message)
            self.operationProgress.emit("Compatibility Lab", 0, 1, "error")
            QTimer.singleShot(8000, lambda: self.operationProgress.emit("Compatibility Lab", 0, 0, "clear"))
            self.statusMessage.emit("Compatibility Lab 失败")
        run_background(worker, completed, failed)

                                                     
    def _build_portability_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        example = {"name":"Portable Pipeline","id":"portable-demo","nodes":[{"id":"source","kind":"source","config":{"base":"${project.base_url}"},"next_ids":["sink"],"failure_ids":[]},{"id":"sink","kind":"sink","config":{},"next_ids":[],"failure_ids":[]}]}
        self.portable_workflow = self._editor(False, json.dumps(example, ensure_ascii=False, indent=2))
        row = QHBoxLayout(); self.portable_export = QPushButton("Export arenyxa.workflow/v1"); self.portable_validate = QPushButton("Validate / Import Document"); self.portable_to_debugger = QPushButton("Imported → Debugger")
        row.addWidget(self.portable_export); row.addWidget(self.portable_validate); row.addWidget(self.portable_to_debugger); row.addStretch()
        self.portable_output = self._editor(True)
        layout.addWidget(QLabel("Reviewable JSON workflow source")); layout.addWidget(self.portable_workflow, 1); layout.addLayout(row); layout.addWidget(QLabel("Canonical portable document / validation result")); layout.addWidget(self.portable_output, 1)
        self.tabs.addTab(tab, "Workflow Portability")
        self.portable_export.clicked.connect(self.export_portable_workflow); self.portable_validate.clicked.connect(self.validate_portable_workflow); self.portable_to_debugger.clicked.connect(self.portable_import_to_debugger)

    def _portable_source_workflow(self) -> Workflow:
        raw = self._json(self.portable_workflow, {})
        return Workflow(name=str(raw.get("name") or "Portable Workflow"), id=str(raw.get("id") or "portable-workflow"), nodes=[WorkflowNode(**item) for item in raw.get("nodes", [])])

    def export_portable_workflow(self) -> None:
        try:
            document = self.context.nextgen.portability.dumps(self._portable_source_workflow())
            self.portable_output.setPlainText(document)
            self.context.nextgen.activity.publish("workflow-portability", "Portable workflow exported", details={"schema":"arenyxa.workflow/v1"})
        except Exception as exc:
            QMessageBox.warning(self, "Workflow Portability", str(exc))

    def validate_portable_workflow(self) -> None:
        try:
            workflow = self.context.nextgen.portability.load(self.portable_output.toPlainText())
            self._last_portable_workflow = workflow
            self.statusMessage.emit(f"Portable Workflow 校验通过 · {len(workflow.nodes)} nodes · SHA-256 verified")
        except Exception as exc:
            QMessageBox.warning(self, "Workflow Portability", str(exc))

    def portable_import_to_debugger(self) -> None:
        try:
            workflow = self._last_portable_workflow or self.context.nextgen.portability.load(self.portable_output.toPlainText())
            self.debug_workflow.setPlainText(json.dumps({"name":workflow.name,"id":workflow.id,"nodes":[asdict(node) for node in workflow.nodes]}, ensure_ascii=False, indent=2))
            self.tabs.setCurrentWidget(self.tabs.widget(7))
            self.statusMessage.emit("Portable Workflow 已发送到 Debugger")
        except Exception as exc:
            QMessageBox.warning(self, "Workflow Portability", str(exc))

                                                            
    def _build_autopilot_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.autopilot_url = QLineEdit("https://example.com")
        self.autopilot_url.setPlaceholderText("授权分析 URL")
        self.autopilot_session = QComboBox(); self.autopilot_session.setMinimumWidth(260)
        self.autopilot_analyze = QPushButton("Analyze Autopilot"); self.autopilot_analyze.setProperty("primary", True)
        self.autopilot_success = QPushButton("Record Success")
        self.autopilot_failure = QPushButton("Record Failure")
        row.addWidget(QLabel("URL")); row.addWidget(self.autopilot_url, 1); row.addWidget(QLabel("Capture")); row.addWidget(self.autopilot_session)
        row.addWidget(self.autopilot_analyze); row.addWidget(self.autopilot_success); row.addWidget(self.autopilot_failure)
        tools = QHBoxLayout()
        self.autopilot_stats = QPushButton("Experience Stats")
        self.autopilot_export = QPushButton("Export Redacted Training JSONL")
        tools.addWidget(self.autopilot_stats); tools.addWidget(self.autopilot_export); tools.addStretch()
        self.autopilot_output = self._editor(True)
        layout.addLayout(row); layout.addLayout(tools)
        layout.addWidget(QLabel("Deterministic strategy + local feedback learning. URLs, DOM, headers, cookies, tokens, and user prompts are not stored by default."))
        layout.addWidget(self.autopilot_output, 1)
        self.tabs.addTab(tab, "Autopilot Learning")
        self.autopilot_analyze.clicked.connect(self.run_autopilot)
        self.autopilot_success.clicked.connect(lambda: self.record_autopilot_feedback(True))
        self.autopilot_failure.clicked.connect(lambda: self.record_autopilot_feedback(False))
        self.autopilot_stats.clicked.connect(self.show_autopilot_stats)
        self.autopilot_export.clicked.connect(self.export_autopilot_dataset)

    def run_autopilot(self) -> None:
        url = self.autopilot_url.text().strip(); session = self.autopilot_session.currentData()
        self.autopilot_output.setPlainText("Working…")
        self.operationProgress.emit("Autopilot", 0, 1, "indeterminate")
        def worker():
            response = self.context.nextgen.request.send(RequestSpec(url)) if url else None
            events = self._capture_events(session)
            plan = self.context.nextgen.autopilot.analyze(response, events)
            return response, events, plan
        def completed(value: object) -> None:
            response, events, plan = value
            self._last_autopilot_response = response
            self._last_autopilot_events = events
            self._last_autopilot_plan = asdict(plan)
            self.autopilot_output.setPlainText(json.dumps(self._last_autopilot_plan, ensure_ascii=False, indent=2, default=str))
            self.context.nextgen.activity.publish(
                "autopilot-plan",
                f"Autopilot analyzed {url or 'capture'}",
                details={"engine": plan.recommended_engine, "confidence": plan.confidence, "site_key": plan.site_key},
            )
            self.operationProgress.emit("Autopilot", 1, 1, "clear")
            self.statusMessage.emit("Analyze Autopilot完成")
        def failed(message: str) -> None:
            self.autopilot_output.setPlainText(message)
            self.operationProgress.emit("Autopilot", 0, 1, "error")
            QTimer.singleShot(8000, lambda: self.operationProgress.emit("Autopilot", 0, 0, "clear"))
            self.statusMessage.emit("Analyze Autopilot失败")
        run_background(worker, completed, failed)

    def record_autopilot_feedback(self, success: bool) -> None:
        if not self._last_autopilot_plan:
            QMessageBox.information(self, "Autopilot", "请先运行一次 Analyze Autopilot。")
            return
        try:
            engine = str(self._last_autopilot_plan.get("recommended_engine", ""))
            diagnosis = self._last_autopilot_plan.get("diagnosis")
            failure_code = None
            if isinstance(diagnosis, dict):
                failure_code = str(diagnosis.get("code") or "") or None
            latency = getattr(self._last_autopilot_response, "elapsed_ms", None)
            self.context.nextgen.autopilot.record_strategy_outcome(
                self._last_autopilot_response,
                self._last_autopilot_events,
                engine,
                success=success,
                latency_ms=latency,
                completeness=1.0 if success else None,
                failure_code=None if success else failure_code or "USER_REPORTED_FAILURE",
            )
            self.context.nextgen.activity.publish("autopilot-feedback", "Autopilot outcome recorded", details={"engine": engine, "success": success})
            self.show_autopilot_stats()
            self.statusMessage.emit("Autopilot 本地反馈已记录；不会上传。")
        except Exception as exc:
            QMessageBox.warning(self, "Autopilot", str(exc))

    def show_autopilot_stats(self) -> None:
        try:
            payload = self.context.nextgen.autopilot.store.stats()
            self.autopilot_output.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2))
        except Exception as exc:
            QMessageBox.warning(self, "Autopilot", str(exc))

    def export_autopilot_dataset(self) -> None:
        try:
            path = self.context.nextgen.autopilot.store.export_training_jsonl(self.context.paths.exports / "arenyxa_autopilot_training.jsonl")
            self.autopilot_output.setPlainText(str(path))
            self.context.nextgen.activity.publish("autopilot-export", "Redacted Autopilot dataset exported", details={"path": path.name})
            self.statusMessage.emit("去标识化训练数据已导出到 Arenyxa Exports。")
        except Exception as exc:
            QMessageBox.warning(self, "Autopilot", str(exc))

                                       
    def _build_live_tab(self) -> None:
        tab = QWidget(); layout = QVBoxLayout(tab)
        controls = QHBoxLayout(); self.live_rate_status = QSpinBox(); self.live_rate_status.setRange(100, 599); self.live_latency = QSpinBox(); self.live_latency.setRange(0, 120_000); self.live_latency.setValue(150); self.live_rate_button = QPushButton("Simulate Adaptive Rate Decision")
        controls.addWidget(QLabel("HTTP status")); controls.addWidget(self.live_rate_status); controls.addWidget(QLabel("latency ms")); controls.addWidget(self.live_latency); controls.addWidget(self.live_rate_button); controls.addStretch()
        run_controls=QHBoxLayout(); self.live_pause=QPushButton("Pause / Resume All"); self.live_cancel=QPushButton("Cancel All"); self.live_limit=QSpinBox(); self.live_limit.setRange(1,max(1,int(self.context.settings.request_concurrency))); self.live_limit.setValue(self.context.runner.request_limit()); self.live_apply_limit=QPushButton("Apply Request Budget"); self.live_auto_limit=QPushButton("Auto Budget")
        run_controls.addWidget(self.live_pause); run_controls.addWidget(self.live_cancel); run_controls.addStretch(); run_controls.addWidget(QLabel("Active request budget")); run_controls.addWidget(self.live_limit); run_controls.addWidget(self.live_apply_limit); run_controls.addWidget(self.live_auto_limit)
        self.live_output = self._editor(True)
        layout.addLayout(controls); layout.addLayout(run_controls); layout.addWidget(self.live_output, 1)
        self.tabs.addTab(tab, "Live Run & Activity Center")
        from arenyxa.application.nextgen import AdaptiveRateLimiter
        self._rate_limiter = AdaptiveRateLimiter(maximum=max(1, int(self.context.settings.request_concurrency)), initial=max(1, int(self.context.settings.per_host_concurrency)))
        self.live_rate_button.clicked.connect(self.simulate_rate)
        self.live_pause.clicked.connect(self.pause_resume_all); self.live_cancel.clicked.connect(self.context.runner.cancel_all); self.live_apply_limit.clicked.connect(self.apply_request_budget); self.live_auto_limit.clicked.connect(self.apply_auto_request_budget)

    def simulate_rate(self) -> None:
        decision = self._rate_limiter.observe(self.live_rate_status.value(), float(self.live_latency.value()))
        self.context.nextgen.activity.publish("rate-limit", decision.reason, details=asdict(decision))
        self.refresh_live()

    def pause_resume_all(self) -> None:
        handles=[handle for handle in self.context.runner.active_handles() if not handle.future.done()]
        for handle in handles:
            if handle.run.status.value == "paused": handle.resume()
            else: handle.pause()
        self.context.nextgen.activity.publish("run-control","Pause/resume applied",details={"runs":len(handles)})
        self.refresh_live()

    def apply_request_budget(self) -> None:
        limit=self.context.runner.set_request_limit(self.live_limit.value())
        self.context.nextgen.activity.publish("concurrency","Request budget changed",details={"request_limit":limit,"mode":"manual"})
        self.refresh_live()

    def apply_auto_request_budget(self) -> None:
        limit = self.context.runner.enable_adaptive_request_limit()
        self.live_limit.setValue(limit)
        self.context.nextgen.activity.publish(
            "concurrency",
            "Adaptive request budget enabled",
            details={"request_limit": limit, "mode": "adaptive"},
        )
        self.refresh_live()

    def refresh_live(self) -> None:
        handles = self.context.runner.active_handles()
        runs = []
        for handle in handles:
            run = handle.run
            runs.append({"id": run.id, "task_id": run.task_id, "status": run.status.value, "stage": run.stage, "completed": run.completed_units, "total": run.total_units, "success": run.success_count, "failure": run.failure_count, "retry": run.retry_count})
        events = [asdict(item) for item in self.context.nextgen.activity.snapshot(150)]
        self.live_output.setPlainText(json.dumps({"active_runs": runs, "concurrency": self.context.runner.concurrency_snapshot(), "adaptive_rate": self.context.runner.adaptive_rate_snapshot(), "activity": events}, ensure_ascii=False, indent=2, default=str))

    def open_section(self, name: str) -> None:
        mapping = {
            "smartpath": 0, "blueprint": 1, "selector": 2, "http": 3, "protocol": 4, "quality": 5,
            "recorder": 6, "debugger": 7, "secrets": 8, "templates": 9, "profiles": 10, "workers": 11,
            "compatibility": 12, "portability": 13, "live": 14, "autopilot": 15,
        }
        index = mapping.get(name)
        if index is not None and 0 <= index < self.tabs.count():
            self.tabs.setCurrentIndex(index)

    def activated(self) -> None:
                                                                             
        captures = self.context.store.list_captures(limit=100)
        for combo in (self.smart_session, self.blueprint_session, self.protocol_session, self.autopilot_session):
            selected = combo.currentData(); combo.clear(); combo.addItem("Latest / Auto", None)
            for capture in captures:
                combo.addItem(f"{capture['created_at'][:19]} · {capture['source_type']} · {capture['event_count']}", capture["id"])
                if capture["id"] == selected: combo.setCurrentIndex(combo.count() - 1)
        self.refresh_live(); self.live_timer.start()

    def deactivated(self) -> None:
        self.live_timer.stop()
