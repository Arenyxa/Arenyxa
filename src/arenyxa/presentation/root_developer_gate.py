from __future__ import annotations

from arenyxa.qt_compat.QtWidgets import (
    QCheckBox,
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


ROOT_CONFIRMATION_TEXT = "ROOT"


class RootDeveloperWarningDialog(QDialog):
    """Deliberate break-glass confirmation before Root Owner authentication.

    This dialog grants no authority. It only establishes explicit user intent before
    the existing certificate, device-key and Root-integrity challenge is started.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Root Developer Authority · 最高风险权限警告")
        self.setModal(True)
        self.setMinimumWidth(700)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("⚠ ROOT DEVELOPER AUTHORITY · 最高技术权限区域")
        title.setWordWrap(True)
        title.setProperty("danger", True)
        layout.addWidget(title)

        warning = QLabel(
            "你正在请求 Arenyxa 的最高技术权限，而不是普通 Developer Mode 或高级设置。\n\n"
            "一旦后续 Root Owner 身份、设备私钥和 Root Integrity Challenge 全部验证成功，"
            "当前进程将建立 platform.root 会话，可触达安全核心调试、Root Authority、"
            "受保护策略与凭据维护等最高级技术能力。\n\n"
            "错误操作可能造成严重且不可逆的后果，包括：\n"
            "• Arenyxa 启动链或安全策略被破坏；\n"
            "• Root / Developer 凭据或信任关系失效；\n"
            "• 工作空间、数据库或企业配置无法正常恢复；\n"
            "• 需要离线恢复、密钥轮换或重新部署才能恢复运行。\n\n"
            "如果你不明确理解 Root Authority、设备密钥、策略回滚和灾难恢复，请取消。"
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)

        boundary = QLabel(
            "安全边界不会因为此确认而降低：Arenyxa 仍会验证 Root Owner Login Bundle、"
            "Owner Device Key、证书信任链和 Root 完整性证明；任何一步失败都会 fail-closed。\n\n"
            "Developer Root Private Key 不会在此登录流程中被请求，应继续保持离线。"
        )
        boundary.setWordWrap(True)
        boundary.setProperty("muted", True)
        layout.addWidget(boundary)

        self.risk_ack = QCheckBox(
            "我明确了解 Root Developer 是最高技术权限，并理解误操作可能造成不可恢复的损坏。"
        )
        self.controlled_device_ack = QCheckBox(
            "我确认当前设备属于受控开发环境，不是普通用户或生产业务终端。"
        )
        self.recovery_ack = QCheckBox(
            "我确认自己具备恢复、回滚或重新部署 Arenyxa 的能力。"
        )
        layout.addWidget(self.risk_ack)
        layout.addWidget(self.controlled_device_ack)
        layout.addWidget(self.recovery_ack)

        confirmation_hint = QLabel(
            f"防误触确认：请手动输入 {ROOT_CONFIRMATION_TEXT}（区分大小写）后才能继续。"
        )
        confirmation_hint.setWordWrap(True)
        layout.addWidget(confirmation_hint)

        self.confirmation = QLineEdit()
        self.confirmation.setPlaceholderText(ROOT_CONFIRMATION_TEXT)
        self.confirmation.setMaxLength(len(ROOT_CONFIRMATION_TEXT))
        layout.addWidget(self.confirmation)

        # Use direct push buttons here because the compatibility wrapper can erase
        # concrete button methods when controls are retrieved indirectly.
        self.continue_button = QPushButton("我已理解风险，继续 Root 登录")
        self.cancel_button = QPushButton("取消")
        self.continue_button.setEnabled(False)
        self.continue_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.continue_button)
        layout.addWidget(self.cancel_button)

        for checkbox in (self.risk_ack, self.controlled_device_ack, self.recovery_ack):
            checkbox.toggled.connect(self._update_continue_state)
        self.confirmation.textChanged.connect(self._update_continue_state)

    def _update_continue_state(self, *_args: object) -> None:
        self.continue_button.setEnabled(
            bool(
                self.risk_ack.isChecked()
                and self.controlled_device_ack.isChecked()
                and self.recovery_ack.isChecked()
                and self.confirmation.text() == ROOT_CONFIRMATION_TEXT
            )
        )

    def accept(self) -> None:
        if not self.continue_button.isEnabled():
            return
        super().accept()


def confirm_root_developer_login(parent: QWidget | None = None) -> bool:
    """Return True only after the explicit break-glass acknowledgement succeeds."""
    dialog = RootDeveloperWarningDialog(parent)
    return dialog.exec() == QDialog.DialogCode.Accepted
