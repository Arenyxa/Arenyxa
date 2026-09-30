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

from arenyxa.presentation.i18n_runtime import current_text


ROOT_CONFIRMATION_TEXT = "ROOT"


class RootDeveloperWarningDialog(QDialog):
    """Deliberate break-glass confirmation before Root Owner authentication.

    This dialog grants no authority. It only establishes explicit user intent before
    the existing certificate, device-key and Root-integrity challenge is started.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(current_text("root_gate.developer.window_title"))
        self.setModal(True)
        self.setMinimumWidth(700)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel(current_text("root_gate.developer.title"))
        title.setWordWrap(True)
        title.setProperty("danger", True)
        layout.addWidget(title)

        warning = QLabel(current_text("root_gate.developer.warning"))
        warning.setWordWrap(True)
        layout.addWidget(warning)

        boundary = QLabel(current_text("root_gate.developer.boundary"))
        boundary.setWordWrap(True)
        boundary.setProperty("muted", True)
        layout.addWidget(boundary)

        self.risk_ack = QCheckBox(current_text("root_gate.developer.risk_ack"))
        self.controlled_device_ack = QCheckBox(current_text("root_gate.developer.controlled_device_ack"))
        self.recovery_ack = QCheckBox(current_text("root_gate.developer.recovery_ack"))
        layout.addWidget(self.risk_ack)
        layout.addWidget(self.controlled_device_ack)
        layout.addWidget(self.recovery_ack)

        confirmation_hint = QLabel(
            current_text("root_gate.developer.confirmation_hint").format(
                confirmation=ROOT_CONFIRMATION_TEXT
            )
        )
        confirmation_hint.setWordWrap(True)
        layout.addWidget(confirmation_hint)

        self.confirmation = QLineEdit()
        self.confirmation.setPlaceholderText(ROOT_CONFIRMATION_TEXT)
        self.confirmation.setMaxLength(len(ROOT_CONFIRMATION_TEXT))
        layout.addWidget(self.confirmation)

        # Use direct push buttons here because the compatibility wrapper can erase
        # concrete button methods when controls are retrieved indirectly.
        self.continue_button = QPushButton(current_text("root_gate.developer.continue"))
        self.cancel_button = QPushButton(current_text("root_gate.common.cancel"))
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
