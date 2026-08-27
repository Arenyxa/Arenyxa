from __future__ import annotations

import json
from typing import Any

from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader
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
    QWidget,
)
from arenyxa.security.dlp import DlpMode, DlpPolicy, GLOBAL_DLP_ENGINE


class DataLossPreventionPage(WorkspacePage):
    def __init__(self, context: Any, theme: Any, motion: Any, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(
            PageHeader(
                "Data Loss Prevention",
                "Central outbound inspection with monitor/enforce policy, trusted destinations and secret-safe findings",
            ),
            1,
        )
        self.apply_button = QPushButton("Apply DLP Policy")
        self.apply_button.setProperty("primary", True)
        self.inspect_button = QPushButton("Inspect Sample")
        header.addWidget(self.inspect_button)
        header.addWidget(self.apply_button)
        root.addLayout(header)

        note = QLabel(
            "DLP is wired into Arenyxa's central HTTP egress path before transport. Monitor mode detects without blocking; "
            "Enforce mode blocks high-risk plaintext credential/private-key egress to untrusted destinations. Secret values are never copied into findings."
        )
        note.setWordWrap(True)
        note.setProperty("muted", True)
        root.addWidget(note)

        panel = QWidget(self)
        form = QFormLayout(panel)
        self.mode = QComboBox(panel)
        self.mode.addItem("Monitor", DlpMode.MONITOR.value)
        self.mode.addItem("Enforce", DlpMode.ENFORCE.value)
        self.mode.addItem("Off", DlpMode.OFF.value)
        self.trusted = QLineEdit(panel)
        self.trusted.setPlaceholderText("corp.example, api.example")
        self.block_plaintext = QCheckBox("Block plaintext credentials to untrusted destinations", panel)
        self.block_plaintext.setChecked(True)
        self.block_private_keys = QCheckBox("Block private-key material to untrusted destinations", panel)
        self.block_private_keys.setChecked(True)
        self.scan_kib = QSpinBox(panel)
        self.scan_kib.setRange(16, 1024)
        self.scan_kib.setValue(256)
        self.scan_kib.setSuffix(" KiB")
        form.addRow("Mode", self.mode)
        form.addRow("Trusted domains", self.trusted)
        form.addRow("Credential policy", self.block_plaintext)
        form.addRow("Private key policy", self.block_private_keys)
        form.addRow("Max body scan", self.scan_kib)
        root.addWidget(panel)

        sample = QWidget(self)
        sample_form = QFormLayout(sample)
        self.sample_url = QLineEdit("http://example.test/upload", sample)
        self.sample_headers = QPlainTextEdit(sample)
        self.sample_headers.setPlaceholderText('{"Authorization":"Bearer sample"}')
        self.sample_body = QPlainTextEdit(sample)
        self.sample_body.setPlaceholderText("Optional request body to classify; values are not persisted by this page.")
        sample_form.addRow("Sample URL", self.sample_url)
        sample_form.addRow("Sample headers (JSON)", self.sample_headers)
        sample_form.addRow("Sample body", self.sample_body)
        root.addWidget(sample, 1)

        self.output = QPlainTextEdit(self)
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("DLP decision output")
        root.addWidget(self.output, 1)

        self.apply_button.clicked.connect(self.apply_policy)
        self.inspect_button.clicked.connect(self.inspect_sample)
        self._load_policy()

    def _policy_from_controls(self) -> DlpPolicy:
        domains = tuple(
            sorted({item.strip().casefold().lstrip(".") for item in self.trusted.text().split(",") if item.strip()})
        )
        return DlpPolicy(
            mode=DlpMode(str(self.mode.currentData() or DlpMode.MONITOR.value)),
            trusted_domains=domains,
            block_plaintext_secrets=self.block_plaintext.isChecked(),
            block_private_keys=self.block_private_keys.isChecked(),
            max_scan_chars=int(self.scan_kib.value()) * 1024,
        )

    @staticmethod
    def _policy_dict(policy: DlpPolicy) -> dict[str, Any]:
        return {
            "mode": policy.mode.value,
            "trusted_domains": list(policy.trusted_domains),
            "block_plaintext_secrets": policy.block_plaintext_secrets,
            "block_private_keys": policy.block_private_keys,
            "max_scan_chars": policy.max_scan_chars,
        }

    def _load_policy(self) -> None:
        policy = GLOBAL_DLP_ENGINE.policy()
        index = self.mode.findData(policy.mode.value)
        if index >= 0:
            self.mode.setCurrentIndex(index)
        self.trusted.setText(", ".join(policy.trusted_domains))
        self.block_plaintext.setChecked(policy.block_plaintext_secrets)
        self.block_private_keys.setChecked(policy.block_private_keys)
        self.scan_kib.setValue(max(16, min(1024, int(policy.max_scan_chars // 1024))))

    def apply_policy(self) -> None:
        try:
            policy = self._policy_from_controls()
            GLOBAL_DLP_ENGINE.configure(policy)
            self.context.store.set_setting("security.dlp_policy", self._policy_dict(policy))
        except (OSError, ValueError, TypeError) as exc:
            QMessageBox.warning(self, "Data Loss Prevention", f"Unable to apply DLP policy: {exc}")
            return
        self.statusMessage.emit(f"DLP policy applied · {policy.mode.value}")
        self.output.setPlainText(json.dumps(self._policy_dict(policy), ensure_ascii=False, indent=2))

    def inspect_sample(self) -> None:
        try:
            raw = self.sample_headers.toPlainText().strip()
            headers = json.loads(raw) if raw else {}
            if not isinstance(headers, dict):
                raise ValueError("headers must be a JSON object")
            decision = GLOBAL_DLP_ENGINE.inspect_http(
                url=self.sample_url.text().strip(),
                headers=headers,
                body=self.sample_body.toPlainText(),
            )
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            QMessageBox.warning(self, "Data Loss Prevention", f"Sample is invalid: {exc}")
            return
        safe = {
            "allowed": decision.allowed,
            "code": decision.code,
            "destination_host": decision.destination_host,
            "findings": [
                {"kind": item.kind, "location": item.location, "severity": item.severity}
                for item in decision.findings
            ],
        }
        self.output.setPlainText(json.dumps(safe, ensure_ascii=False, indent=2))
        self.inspectorChanged.emit("Data Loss Prevention", safe)
