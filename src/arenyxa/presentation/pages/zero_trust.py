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
from arenyxa.security.zero_trust import ZeroTrustEvaluator, ZeroTrustPolicy
from arenyxa.security.confidential_compute import ConfidentialComputePolicy
from arenyxa.domain.errors import ArenyxaError


class ZeroTrustPage(WorkspacePage):
    def __init__(self, context: Any, theme: Any, motion: Any, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(
            PageHeader(
                "Zero Trust Access",
                "Identity plus real-time device posture, MFA freshness, network trust and risk-aware Enterprise authorization",
            ),
            1,
        )
        self.evaluate_button = QPushButton("Evaluate Context")
        self.apply_button = QPushButton("Apply to Resource")
        self.apply_button.setProperty("primary", True)
        self.apply_server_button = QPushButton("Apply Server Security Policy")
        header.addWidget(self.evaluate_button)
        header.addWidget(self.apply_server_button)
        header.addWidget(self.apply_button)
        root.addLayout(header)

        note = QLabel(
            "Policies are stored with Enterprise resources and evaluated during authorize_operation(). Missing context fails closed when a Zero Trust policy is enabled."
        )
        note.setWordWrap(True)
        note.setProperty("muted", True)
        root.addWidget(note)
        root.addWidget(self._build_policy_panel())
        root.addWidget(self._build_context_panel())

        self.output = QPlainTextEdit(self)
        self.output.setReadOnly(True)
        root.addWidget(self.output, 1)
        self.evaluate_button.clicked.connect(self.evaluate_context)
        self.apply_button.clicked.connect(self.apply_resource_policy)
        self.apply_server_button.clicked.connect(self.apply_server_policy)

    def _build_policy_panel(self) -> QWidget:
        panel = QWidget(self)
        form = QFormLayout(panel)
        self.resource_id = QLineEdit(panel)
        self.resource_id.setPlaceholderText("dataset:example or workflow:example")
        self.enabled = QCheckBox("Enable dynamic Zero Trust gate", panel)
        self.managed = QCheckBox("Require managed device", panel)
        self.compliant = QCheckBox("Require compliant device", panel)
        self.mfa = QCheckBox("Require MFA", panel)
        self.network = QComboBox(panel)
        self.network.addItem("Trusted only", "trusted")
        self.network.addItem("Trusted + private", "trusted,private")
        self.network.addItem("Trusted + private + unknown", "trusted,private,unknown")
        self.max_risk = QSpinBox(panel)
        self.max_risk.setRange(0, 100)
        self.max_risk.setValue(50)
        self.max_auth_age = QSpinBox(panel)
        self.max_auth_age.setRange(30, 86400)
        self.max_auth_age.setValue(3600)
        self.max_auth_age.setSuffix(" s")
        self.allowed_cidrs = QLineEdit(panel)
        self.allowed_cidrs.setPlaceholderText("10.20.0.0/16, 192.168.50.0/24")
        self.required_permissions = QLineEdit(panel)
        self.required_permissions.setPlaceholderText("dataset.read, worker.execute")
        self.allowed_workers = QLineEdit(panel)
        self.allowed_workers.setPlaceholderText("worker-a, worker-b (optional)")
        self.allowed_servers = QLineEdit(panel)
        self.allowed_servers.setPlaceholderText("server-primary (optional)")
        self.require_relay = QCheckBox("Require Server relay", panel)
        self.deny_p2p = QCheckBox("Deny Worker peer-to-peer", panel)
        self.required_transport = QComboBox(panel)
        self.required_transport.addItem("Any", "")
        self.required_transport.addItem("TLS 1.3", "tls13")
        self.required_transport.addItem("TLS 1.2", "tls12")
        self.required_transport.addItem("Local IPC", "local")
        self.confidential_mode = QComboBox(panel)
        self.confidential_mode.addItem("Off · software verification", "off")
        self.confidential_mode.addItem("Prefer attested TEE", "prefer")
        self.confidential_mode.addItem("Require attested TEE · fail closed", "require")
        for label, widget in (
            ("Enterprise resource", self.resource_id), ("Policy", self.enabled),
            ("Device management", self.managed), ("Device compliance", self.compliant),
            ("MFA", self.mfa), ("Allowed network trust", self.network),
            ("Maximum risk score", self.max_risk), ("Maximum auth age", self.max_auth_age),
            ("Allowed source CIDRs", self.allowed_cidrs), ("Required permissions", self.required_permissions),
            ("Allowed Worker IDs", self.allowed_workers), ("Allowed Server IDs", self.allowed_servers),
            ("Server relay", self.require_relay), ("Peer isolation", self.deny_p2p),
            ("Required transport", self.required_transport),
            ("Confidential compute", self.confidential_mode),
        ):
            form.addRow(label, widget)
        return panel

    def _build_context_panel(self) -> QWidget:
        panel = QWidget(self)
        form = QFormLayout(panel)
        self.ctx_managed = QCheckBox("Managed", panel)
        self.ctx_compliant = QCheckBox("Compliant", panel)
        self.ctx_mfa = QCheckBox("MFA verified", panel)
        self.ctx_network = QComboBox(panel)
        for item in ("trusted", "private", "untrusted", "unknown"):
            self.ctx_network.addItem(item, item)
        self.ctx_risk = QSpinBox(panel)
        self.ctx_risk.setRange(0, 100)
        self.ctx_risk.setValue(20)
        self.ctx_auth_age = QSpinBox(panel)
        self.ctx_auth_age.setRange(0, 604800)
        self.ctx_auth_age.setValue(60)
        self.ctx_auth_age.setSuffix(" s")
        self.ctx_source_ip = QLineEdit(panel)
        self.ctx_source_ip.setPlaceholderText("10.20.4.18")
        self.ctx_permissions = QLineEdit(panel)
        self.ctx_permissions.setPlaceholderText("dataset.read, worker.execute")
        self.ctx_worker_id = QLineEdit(panel)
        self.ctx_server_id = QLineEdit(panel)
        self.ctx_relay = QCheckBox("Via Server relay", panel)
        self.ctx_peer = QCheckBox("Peer-to-peer request", panel)
        self.ctx_transport = QComboBox(panel)
        for label, value in (("TLS 1.3", "tls13"), ("TLS 1.2", "tls12"), ("Local IPC", "local"), ("Unknown", "")):
            self.ctx_transport.addItem(label, value)
        for label, widget in (
            ("Context device", self.ctx_managed), ("Context compliance", self.ctx_compliant),
            ("Context MFA", self.ctx_mfa), ("Context network", self.ctx_network),
            ("Context risk", self.ctx_risk), ("Context auth age", self.ctx_auth_age),
            ("Source IP", self.ctx_source_ip), ("Effective permissions", self.ctx_permissions),
            ("Worker ID", self.ctx_worker_id), ("Server ID", self.ctx_server_id),
            ("Relay path", self.ctx_relay), ("Peer traffic", self.ctx_peer),
            ("Transport", self.ctx_transport),
        ):
            form.addRow(label, widget)
        return panel

    def _policy(self) -> ZeroTrustPolicy:
        allowed = tuple(item for item in str(self.network.currentData() or "trusted").split(",") if item)
        return ZeroTrustPolicy(
            enabled=self.enabled.isChecked(),
            require_managed_device=self.managed.isChecked(),
            require_compliant_device=self.compliant.isChecked(),
            require_mfa=self.mfa.isChecked(),
            allowed_network_trust=allowed,
            max_risk_score=int(self.max_risk.value()),
            max_auth_age_seconds=int(self.max_auth_age.value()),
            allowed_source_cidrs=tuple(item.strip() for item in self.allowed_cidrs.text().split(",") if item.strip()),
            required_permissions=tuple(item.strip() for item in self.required_permissions.text().split(",") if item.strip()),
            allowed_worker_ids=tuple(item.strip() for item in self.allowed_workers.text().split(",") if item.strip()),
            allowed_server_ids=tuple(item.strip() for item in self.allowed_servers.text().split(",") if item.strip()),
            require_server_relay=self.require_relay.isChecked(),
            deny_peer_to_peer=self.deny_p2p.isChecked(),
            required_transport=str(self.required_transport.currentData() or ""),
        )

    def _context(self) -> dict[str, Any]:
        return {
            "managed_device": self.ctx_managed.isChecked(),
            "device_compliant": self.ctx_compliant.isChecked(),
            "mfa_verified": self.ctx_mfa.isChecked(),
            "network_trust": str(self.ctx_network.currentData() or "unknown"),
            "risk_score": int(self.ctx_risk.value()),
            "auth_age_seconds": int(self.ctx_auth_age.value()),
            "source_ip": self.ctx_source_ip.text().strip(),
            "permissions": tuple(item.strip() for item in self.ctx_permissions.text().split(",") if item.strip()),
            "worker_id": self.ctx_worker_id.text().strip(),
            "server_id": self.ctx_server_id.text().strip(),
            "via_server_relay": self.ctx_relay.isChecked(),
            "peer_to_peer": self.ctx_peer.isChecked(),
            "transport": str(self.ctx_transport.currentData() or ""),
        }

    def evaluate_context(self) -> None:
        policy = self._policy()
        decision = ZeroTrustEvaluator.evaluate(policy, self._context())
        safe = {
            "allowed": decision.allowed,
            "code": decision.code,
            "reasons": list(decision.reasons),
            "risk_score": decision.risk_score,
            "policy": policy.as_dict(),
        }
        self.output.setPlainText(json.dumps(safe, ensure_ascii=False, indent=2))
        self.inspectorChanged.emit("Zero Trust Access", safe)

    def apply_resource_policy(self) -> None:
        resource = self.resource_id.text().strip()
        if not resource:
            QMessageBox.information(self, "Zero Trust Access", "Enter an Enterprise resource ID first.")
            return
        governance = getattr(self.context, "enterprise_governance", None)
        if governance is None:
            QMessageBox.warning(self, "Zero Trust Access", "Enterprise governance is unavailable in this runtime.")
            return
        try:
            stored = governance.set_zero_trust_policy(resource, self._policy())
        except (ArenyxaError, RuntimeError, ValueError, TypeError, OSError) as exc:
            QMessageBox.warning(self, "Zero Trust Access", f"Policy update denied or failed: {exc}")
            return
        self.output.setPlainText(json.dumps({"resource_id": resource, "policy": stored}, ensure_ascii=False, indent=2))
        self.statusMessage.emit(f"Zero Trust policy updated · {resource}")
    def apply_server_policy(self) -> None:
        runtime = getattr(self.context, "enterprise_server", None)
        if runtime is None:
            QMessageBox.warning(self, "Zero Trust Access", "Enterprise Server runtime is unavailable.")
            return
        try:
            network = runtime.set_network_policy(self._policy())
            confidential = runtime.set_confidential_compute_policy(
                ConfidentialComputePolicy(mode=str(self.confidential_mode.currentData() or "off"))
            )
        except (ArenyxaError, RuntimeError, ValueError, TypeError, OSError) as exc:
            QMessageBox.warning(self, "Zero Trust Access", f"Server security policy update denied or failed: {exc}")
            return
        self.output.setPlainText(
            json.dumps(
                {"enterprise_server_network_policy": network, "confidential_compute": confidential},
                ensure_ascii=False, indent=2,
            )
        )
        self.statusMessage.emit("Enterprise Server security policy updated")

