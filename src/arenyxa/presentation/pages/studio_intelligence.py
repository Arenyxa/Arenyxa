from __future__ import annotations

from arenyxa.application.autopilot_validation import AutopilotProductionValidator

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


class StudioIntelligenceMixin:
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
