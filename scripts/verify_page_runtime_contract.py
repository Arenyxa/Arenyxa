from __future__ import annotations

"""Guard lazy-loaded GUI pages against Qt API and construction-order regressions."""

import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PAGES = SRC / "arenyxa" / "presentation" / "pages"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


FORBIDDEN_HEADER_CHAINS = (
    ".horizontalHeader().setStretchLastSection",
    ".horizontalHeader().setSectionResizeMode",
)


def verify_static_contract() -> None:
    violations: list[str] = []
    for path in sorted(PAGES.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_HEADER_CHAINS:
            if token in source:
                violations.append(f"{path.name}: direct Qt header chain {token}")
    if violations:
        raise RuntimeError("; ".join(violations))

    extraction = (PAGES / "extraction.py").read_text(encoding="utf-8")
    for token in (
        "set_table_header_stretch_last(self.fields, True)",
        "set_table_header_stretch_last(self.recipe_steps, True)",
    ):
        if token not in extraction:
            raise RuntimeError(f"Extraction Lab missing Qt-safe header helper: {token}")

    proxy = (PAGES / "proxy.py").read_text(encoding="utf-8")
    summary_start = proxy.index("    def _build_session_summary_tab")
    deep_start = proxy.index("    def _build_deep_analysis_tab")
    summary = proxy[summary_start:deep_start]
    if any(name in summary for name in ("deep_inspect_button", "deep_compare_button", "deep_timeline_button")):
        raise RuntimeError("Proxy Session Summary must not access Deep Analysis controls before construction")
    deep_end = proxy.find("\n    def ", deep_start + 5)
    deep = proxy[deep_start : deep_end if deep_end > 0 else len(proxy)]
    for name in ("deep_inspect_button", "deep_compare_button", "deep_timeline_button"):
        assignment = f"self.{name} = QPushButton"
        connection = f"self.{name}.clicked.connect"
        if assignment not in deep or connection not in deep or deep.index(assignment) > deep.index(connection):
            raise RuntimeError(f"Proxy control is connected before construction: {name}")


def verify_runtime_pages_when_qt_available() -> str:
    from arenyxa.qt_compat import binding_available

    if not binding_available():
        return "SKIP (Qt binding unavailable in validation environment)"

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from arenyxa.qt_compat.QtWidgets import QApplication
    from arenyxa.presentation.pages.extraction import ExtractionStudioPage
    from arenyxa.presentation.pages.proxy import ProxyPage

    app = QApplication.instance() or QApplication([])
    del app  # QApplication lifetime is held by Qt; this only silences static analyzers.

    class _FakeCA:
        @staticmethod
        def fingerprint() -> str:
            return "00" * 32

    class _FakeProxyEngine:
        ca = _FakeCA()

        @staticmethod
        def autoresponder_rules() -> list[dict[str, object]]:
            return []

        @staticmethod
        def match_replace_rules() -> list[dict[str, object]]:
            return []

    with tempfile.TemporaryDirectory(prefix="arenyxa-page-smoke-") as raw:
        captures = Path(raw) / "captures"
        captures.mkdir(parents=True, exist_ok=True)
        context = SimpleNamespace(paths=SimpleNamespace(captures=captures), proxy_engine=_FakeProxyEngine())
        theme = SimpleNamespace()
        motion = SimpleNamespace()
        extraction = ExtractionStudioPage(context, theme, motion)
        proxy = ProxyPage(context, theme, motion)
        extraction.close()
        proxy.close()
    return "PASS"


def main() -> int:
    verify_static_contract()
    runtime = verify_runtime_pages_when_qt_available()
    print("Arenyxa lazy page runtime contract: PASS")
    print("- Qt-safe table header usage: PASS")
    print("- Proxy construction order: PASS")
    print(f"- runtime page construction: {runtime}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
