"""Single top-level Arenyxa startup shell and in-window Root challenge experience."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from arenyxa.presentation.i18n_runtime import current_text
from arenyxa.presentation.startup_motion_math import smootherstep, startup_progress_duration_ms
from arenyxa.qt_compat.QtCore import QEventLoop, QTimer, Qt, Signal, QVariantAnimation
from arenyxa.qt_compat.QtGui import QCloseEvent, QIcon, QPalette
from arenyxa.qt_compat.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)


_STARTUP_ACTIVITY_KEYS = {
    "settings": "settings",
    "Root workstation": "root_workstation",
    "performance": "performance",
    "database": "database",
    "recovery": "recovery",
    "resource governor": "resource_governor",
    "Security Kernel": "security_kernel",
    "Developer and Root": "developer_root",
    "Enterprise": "enterprise",
    "scheduler": "scheduler",
    "workflow": "workflow",
    "packet capture": "packet_capture",
    "proxy": "proxy",
    "runtime supervisor": "runtime_supervisor",
    "resilience": "resilience",
    "navigation": "navigation",
    "persisted schedules": "persisted_schedules",
    "Ready": "ready",
}


def _startup_key(label: str) -> str | None:
    folded = str(label).casefold()
    for needle, key in _STARTUP_ACTIVITY_KEYS.items():
        if needle.casefold() in folded:
            return key
    return None


def _startup_activity_hint(label: str) -> str:
    key = _startup_key(label)
    return current_text(f"shell.startup.hint.{key}") if key else current_text("shell.startup.hint.default")


def _startup_state_text(label: str) -> str:
    key = _startup_key(label)
    return current_text(f"shell.startup.state.{key}") if key else str(label)


class SplashPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ArenyxaShellSplashPage")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(56, 48, 56, 48)
        layout.addStretch()
        title = QLabel("Arenyxa")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size:42px;font-weight:750;")
        subtitle = QLabel(current_text("shell.startup.subtitle"))
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("font-size:15px;")
        self.state = QLabel(current_text("shell.startup.environment_check"))
        self.state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.activity = QLabel(current_text("shell.startup.hint.default"))
        self.activity.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.activity.setProperty("muted", True)
        self.activity.setStyleSheet("font-size:12px;opacity:0.82;")
        self.progress = QProgressBar()
        self.progress.setObjectName("ArenyxaStartupProgress")

        # ThemeManager applies a global QProgressBar rule while MainWindow is being
        # constructed. Without a local style, the still-visible startup bar changes
        # accent (for example blue -> green) and metrics at 100%. Capture the native
        # startup palette/height once and keep that exact presentation through handoff.
        startup_palette = self.progress.palette()
        startup_chunk = startup_palette.color(QPalette.ColorRole.Highlight).name()
        startup_track = startup_palette.color(QPalette.ColorRole.Base).name()
        startup_text = startup_palette.color(QPalette.ColorRole.Text).name()
        startup_height = max(12, int(self.progress.sizeHint().height()))
        self.progress.setFixedHeight(startup_height)
        self.progress.setStyleSheet(
            "QProgressBar#ArenyxaStartupProgress {"
            f"background-color:{startup_track}; color:{startup_text};"
            "border:0; border-radius:3px; text-align:center; padding:0;"
            "}"
            "QProgressBar#ArenyxaStartupProgress::chunk {"
            f"background-color:{startup_chunk}; border:0; border-radius:3px;"
            "}"
        )
        # Keep the public percentage presentation unchanged while rendering ten
        # visual steps per percentage point.  Sparse bootstrap milestones then
        # move as a continuous blue bar instead of jumping in whole percentages.
        self._progress_scale = 10
        self.progress.setRange(0, 100 * self._progress_scale)
        self.progress.setValue(0)
        self.progress.setFormat("%p%")
        self.progress.setTextVisible(True)
        self._progress_target = 0
        self._progress_animation: QVariantAnimation | None = None
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(32)
        layout.addWidget(self.state)
        layout.addWidget(self.activity)
        layout.addWidget(self.progress)
        layout.addStretch()

    def set_state(self, text: str, *, ready: bool = False) -> None:
        self.state.setText(_startup_state_text(str(text)))
        self.activity.setText(_startup_activity_hint(str(text)))
        if ready:
            self.set_stage(100, text)

    def set_stage(self, percent: int, label: str) -> None:
        bounded = max(0, min(100, int(percent)))
        self.state.setText(f"{bounded}% · {_startup_state_text(label)}")
        self.activity.setText(_startup_activity_hint(label))
        target = max(self.progress.value(), bounded * self._progress_scale)
        if target <= self.progress.value():
            self._progress_target = target
            return
        self._animate_progress_to(target)

    def _animate_progress_to(self, target: int) -> None:
        """Smoothly pursue one authoritative bootstrap milestone.

        Bootstrap intentionally remains synchronous on the GUI thread.  A short
        local Qt event loop is used only for this cosmetic transition so the
        existing bootstrap ordering/threading/security behavior stays unchanged.
        """
        target = max(self.progress.value(), min(self.progress.maximum(), int(target)))
        start = self.progress.value()
        self._progress_target = target
        if start >= target:
            return

        old = self._progress_animation
        if old is not None:
            old.stop()

        start_percent = start / self._progress_scale
        target_percent = target / self._progress_scale
        duration_ms = startup_progress_duration_ms(start_percent, target_percent)
        if duration_ms <= 0:
            self.progress.setValue(target)
            return

        animation = QVariantAnimation(self)
        self._progress_animation = animation
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setDuration(duration_ms)

        def update(value: object) -> None:
            phase = smootherstep(float(value))
            visual = start + (target - start) * phase
            self.progress.setValue(min(target, int(round(visual))))

        loop = QEventLoop()
        guard = QTimer(loop)
        guard.setSingleShot(True)
        guard.setInterval(duration_ms + 80)
        guard.timeout.connect(loop.quit)

        def complete() -> None:
            self.progress.setValue(target)
            if self._progress_animation is animation:
                self._progress_animation = None
            guard.stop()
            loop.quit()

        animation.valueChanged.connect(update)
        animation.finished.connect(complete)
        # Defensive guard: never let a cosmetic animation become a startup blocker.
        guard.start()
        animation.start()
        loop.exec()
        if self.progress.value() < target:
            self.progress.setValue(target)
        if self._progress_animation is animation:
            animation.stop()
            self._progress_animation = None


class AuthenticationPage(QWidget):
    verifyRequested = Signal(str, str)
    continueNormalRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ArenyxaShellAuthenticationPage")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(72, 52, 72, 52)
        outer.addStretch()
        card = QFrame()
        card.setObjectName("RootAuthorityChallenge")
        card.setMaximumWidth(760)
        layout = QVBoxLayout(card)
        title = QLabel(current_text("shell.root.title"))
        title.setStyleSheet("font-size:28px;font-weight:700;")
        detail = QLabel(current_text("shell.root.detail"))
        detail.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(detail)
        form = QFormLayout()
        self.device_identity = QLabel(current_text("shell.common.unknown"))
        self.tpm_status = QLabel(current_text("shell.common.unknown"))
        self.challenge_fingerprint = QLabel(current_text("shell.common.pending"))
        self.verification_state = QLabel(current_text("shell.root.waiting"))
        self.verification_state.setWordWrap(True)
        form.addRow(current_text("shell.root.device_identity"), self.device_identity)
        form.addRow(current_text("shell.root.tpm_status"), self.tpm_status)
        form.addRow(current_text("shell.root.challenge_fingerprint"), self.challenge_fingerprint)
        form.addRow(current_text("shell.root.verification_state"), self.verification_state)
        layout.addLayout(form)
        vault_row = QHBoxLayout()
        self.vault_path = QLineEdit()
        self.vault_path.setPlaceholderText(current_text("shell.root.vault_placeholder"))
        browse = QPushButton(current_text("shell.common.browse"))
        browse.clicked.connect(self._browse)
        vault_row.addWidget(self.vault_path, 1)
        vault_row.addWidget(browse)
        layout.addLayout(vault_row)
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase.setPlaceholderText(current_text("shell.root.passphrase_placeholder"))
        layout.addWidget(self.passphrase)
        actions = QHBoxLayout()
        self.verify_button = QPushButton(current_text("shell.root.verify"))
        self.verify_button.setProperty("primary", True)
        # A registered Root workstation is fail-closed.  There is no ordinary
        # desktop-session bypass after a failed Root Owner challenge.
        self.continue_button = QPushButton(current_text("shell.root.continue_normal"))
        self.continue_button.setVisible(False)
        self.continue_button.setEnabled(False)
        actions.addStretch()
        actions.addWidget(self.continue_button)
        actions.addWidget(self.verify_button)
        layout.addLayout(actions)
        self.verify_button.clicked.connect(self._verify)
        self.continue_button.clicked.connect(self.continueNormalRequested.emit)
        centered = QHBoxLayout()
        centered.addStretch()
        centered.addWidget(card)
        centered.addStretch()
        outer.addLayout(centered)
        outer.addStretch()

    def configure(
        self,
        *,
        device_identity: str,
        tpm_status: str,
        fingerprint: str,
    ) -> None:
        self.device_identity.setText(device_identity or current_text("shell.root.registered_device"))
        self.tpm_status.setText(tpm_status or current_text("shell.root.not_reported"))
        self.challenge_fingerprint.setText(fingerprint or current_text("shell.root.pending_challenge"))
        self.verification_state.setText(current_text("shell.root.waiting"))
        self.verify_button.setEnabled(True)
        self.continue_button.setVisible(False)
        self.continue_button.setEnabled(False)

    def set_verifying(self) -> None:
        self.verify_button.setEnabled(False)
        self.verification_state.setText(current_text("shell.root.verifying"))

    def set_authenticated(self) -> None:
        self.passphrase.clear()
        self.verification_state.setText(current_text("shell.root.authenticated"))

    def set_failed(self, message: str) -> None:
        self.passphrase.clear()
        self.verify_button.setEnabled(True)
        self.continue_button.setVisible(False)
        self.continue_button.setEnabled(False)
        self.verification_state.setText(
            current_text("shell.root.failed").format(message=str(message)[:512])
        )

    def _browse(self) -> None:
        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            current_text("shell.root.select_vault"),
            str(Path(self.vault_path.text()).parent) if self.vault_path.text() else "",
            current_text("shell.root.vault_filter"),
        )
        if path:
            self.vault_path.setText(path)

    def _verify(self) -> None:
        path = self.vault_path.text().strip()
        passphrase = self.passphrase.text()
        if not path or not passphrase:
            self.set_failed(current_text("shell.root.missing_credentials"))
            return
        self.set_verifying()
        self.verifyRequested.emit(path, passphrase)


class MainPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ArenyxaShellMainPage")
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

    def attach(self, window: QMainWindow) -> None:
        window.setParent(self)
        window.setWindowFlags(Qt.Widget)
        self.layout.addWidget(window)
        window.show()


class RecoveryPage(QWidget):
    continueRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(64, 56, 64, 56)
        title = QLabel(current_text("shell.recovery.title"))
        title.setStyleSheet("font-size:28px;font-weight:700;")
        self.message = QLabel()
        self.message.setWordWrap(True)
        self.message.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.continue_button = QPushButton(current_text("shell.recovery.continue"))
        self.continue_button.setProperty("primary", True)
        self.continue_button.clicked.connect(self.continueRequested.emit)
        layout.addWidget(title)
        layout.addWidget(self.message, 1)
        layout.addWidget(self.continue_button, 0, Qt.AlignmentFlag.AlignRight)


class ArenyxaShellWindow(QMainWindow):
    """The only top-level window used during normal Arenyxa process startup."""

    closeRequested = Signal()

    def __init__(
        self,
        *,
        geometry: Any | None = None,
        icon_path: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("ArenyxaShellWindow")
        self.setWindowTitle("Arenyxa")
        self.setMinimumSize(960, 640)
        if geometry is not None and geometry.isValid():
            self.setGeometry(geometry)
        else:
            self.resize(1280, 800)
        if icon_path is not None and Path(icon_path).is_file():
            self.setWindowIcon(QIcon(str(icon_path)))
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.splash_page = SplashPage()
        self.authentication_page = AuthenticationPage()
        self.main_page = MainPage()
        self.recovery_page = RecoveryPage()
        for page in (
            self.splash_page,
            self.authentication_page,
            self.main_page,
            self.recovery_page,
        ):
            self.stack.addWidget(page)
        self.stack.setCurrentWidget(self.splash_page)
        self.main_window: QMainWindow | None = None
        self._closing = False
        self._splash_started_ms = 0

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._closing:
            super().closeEvent(event)
            return
        self._closing = True
        main_window = self.main_window
        if main_window is not None and main_window.isVisible():
            # Let MainWindow run its own persistence/background-shutdown path first.
            main_window.close()
            if main_window.isVisible():
                event.ignore()
                self._closing = False
                return
        self.closeRequested.emit()
        super().closeEvent(event)

    def show_splash(self, state: str = "Environment check") -> None:
        if not self._splash_started_ms:
            from time import monotonic

            self._splash_started_ms = int(monotonic() * 1000)
        self.splash_page.set_state(state)
        self.stack.setCurrentWidget(self.splash_page)

    def show_bootstrap_stage(self, percent: int, label: str) -> None:
        self.splash_page.set_stage(percent, label)
        self.stack.setCurrentWidget(self.splash_page)

    def ensure_splash_minimum(self, minimum_ms: int = 1000) -> None:
        if not self._splash_started_ms:
            return
        from time import monotonic

        elapsed = int(monotonic() * 1000) - self._splash_started_ms
        remaining = max(0, int(minimum_ms) - elapsed)
        if remaining:
            loop = QEventLoop(self)
            QTimer.singleShot(remaining, loop.quit)
            loop.exec()

    def show_authentication(self, **details: str) -> None:
        self.authentication_page.configure(**details)
        self.stack.setCurrentWidget(self.authentication_page)

    def attach_main_window(self, window: QMainWindow) -> None:
        if self.main_window is not None and self.main_window is not window:
            raise RuntimeError("ArenyxaShellWindow already owns a MainWindow")
        self.main_window = window
        self.main_page.attach(window)
        close_requested = getattr(window, "shellCloseRequested", None)
        if close_requested is not None:
            close_requested.connect(self.hide)

    def show_main(self) -> None:
        if self.main_window is None:
            raise RuntimeError("Main UI has not been attached")
        self.stack.setCurrentWidget(self.main_page)

    def show_recovery(self, message: str) -> None:
        self.recovery_page.message.setText(str(message))
        self.stack.setCurrentWidget(self.recovery_page)

    def show_recovered_session(
        self,
        *,
        previous_task: str,
        previous_capture: str,
        previous_state: str,
    ) -> None:
        self.show_recovery(
            "Unexpected shutdown detected\n\n"
            "Recovered session:\n"
            f"Previous task: {previous_task or 'None'}\n"
            f"Previous capture: {previous_capture or 'None'}\n"
            f"Previous state: {previous_state or 'Unknown'}"
        )
