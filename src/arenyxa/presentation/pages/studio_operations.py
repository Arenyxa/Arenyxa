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


class StudioOperationsMixin:
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
        self.autopilot_validate = QPushButton("Run Stability Validation")
        tools.addWidget(self.autopilot_stats); tools.addWidget(self.autopilot_validate); tools.addWidget(self.autopilot_export); tools.addStretch()
        self.autopilot_output = self._editor(True)
        layout.addLayout(row); layout.addLayout(tools)
        layout.addWidget(QLabel("Experimental local deterministic learning. It is advisory only and cannot override execution safety, authorization, or deterministic Workflow behavior."))
        layout.addWidget(self.autopilot_output, 1)
        self.tabs.addTab(tab, "Autopilot Learning")
        self.autopilot_analyze.clicked.connect(self.run_autopilot)
        self.autopilot_success.clicked.connect(lambda: self.record_autopilot_feedback(True))
        self.autopilot_failure.clicked.connect(lambda: self.record_autopilot_feedback(False))
        self.autopilot_stats.clicked.connect(self.show_autopilot_stats)
        self.autopilot_export.clicked.connect(self.export_autopilot_dataset)
        self.autopilot_validate.clicked.connect(self.run_autopilot_validation)

    def run_autopilot_validation(self) -> None:
        self.autopilot_validate.setEnabled(False)
        self.operationProgress.emit("Autopilot Validation", 0, 1, "indeterminate")

        def worker() -> object:
            return AutopilotProductionValidator(samples=200).run().to_dict()

        def completed(value: object) -> None:
            self.autopilot_validate.setEnabled(True)
            payload = dict(value) if isinstance(value, dict) else {"result": value}
            self.autopilot_output.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            stable = bool(payload.get("stable"))
            self.operationProgress.emit("Autopilot Validation", 1, 1, "clear" if stable else "error")
            self.statusMessage.emit("Autopilot stability validation passed" if stable else "Autopilot stability validation found a regression")

        def failed(message: str) -> None:
            self.autopilot_validate.setEnabled(True)
            self.autopilot_output.setPlainText(message)
            self.operationProgress.emit("Autopilot Validation", 0, 1, "error")
            self.statusMessage.emit("Autopilot stability validation failed")

        run_background(worker, completed, failed)

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
