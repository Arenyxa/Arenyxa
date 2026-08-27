from __future__ import annotations

from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    welcome = (root / "src/arenyxa/presentation/pages/welcome.py").read_text(encoding="utf-8")
    main_window = (root / "src/arenyxa/presentation/main_window.py").read_text(encoding="utf-8")
    navigation = (root / "src/arenyxa/presentation/main_window_navigation.py").read_text(encoding="utf-8")
    app = (root / "src/arenyxa/app.py").read_text(encoding="utf-8")
    window_surface = main_window + "\n" + navigation
    checks = {
        "top-level QDialog": "class WelcomeCenterDialog(QDialog)" in welcome and "super().__init__(None)" in welcome,
        "not workspace page": 'self.pages["welcome"]' not in window_surface,
        "welcome navigation implementation": "def show_welcome_center" in navigation,
        "modal execution": "dialog.exec()" in window_surface,
        "post-startup scheduling": "window.show_pending_welcome()" in app,
    }
    failed = [label for label, ok in checks.items() if not ok]
    if failed:
        print("Welcome window contract: FAIL")
        for item in failed:
            print("- " + item)
        return 1
    print("Welcome window contract: PASS")
    for item in checks:
        print("- " + item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
