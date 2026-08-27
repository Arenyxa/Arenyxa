from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def _class_bases(path: Path, class_name: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    node = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == class_name)
    bases: set[str] = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            bases.add(base.id)
        elif isinstance(base, ast.Attribute):
            bases.add(base.attr)
    return bases


def test_large_modules_are_split_behind_stable_public_classes() -> None:
    cases = [
        (SRC / "infrastructure/capture/protocol_application.py", "ApplicationProtocolMixin", {"ApplicationProtocolServiceMixin", "ApplicationProtocolWebMixin"}),
        (SRC / "infrastructure/capture/packet_analysis.py", "PacketAnalysisEngine", {"PacketAnalysisNativeMixin"}),
        (SRC / "application/workflow_runtime.py", "WorkflowDatasetService", {"WorkflowExecutionMixin", "WorkflowResumeMixin", "WorkflowRuntimeEngineMixin"}),
        (SRC / "presentation/pages/enterprise.py", "EnterprisePage", {"EnterpriseIdentityActionsMixin", "EnterpriseDistributedActionsMixin"}),
        (SRC / "presentation/pages/studio.py", "IntelligenceStudioPage", {"StudioIntelligenceMixin", "StudioOperationsMixin"}),
        (SRC / "presentation/pages/network.py", "NetworkPage", {"NetworkCaptureActionsMixin", "NetworkAnalysisActionsMixin"}),
        (SRC / "application/command_runtime_professional.py", "CommandProfessionalMixin", {"CommandPacketMixin", "CommandAutomationMixin", "CommandProxyMixin"}),
    ]
    for path, class_name, expected in cases:
        assert expected <= _class_bases(path, class_name), (path, class_name)


def test_tools_module_remains_a_compatibility_facade() -> None:
    source = (SRC / "presentation/pages/tools.py").read_text(encoding="utf-8")
    for name in (
        "AutomationPage",
        "WorkflowPage",
        "AdvancedPlatformPage",
        "PluginsPage",
        "ConsoleCommandEdit",
        "ConsolePage",
        "LogsPage",
    ):
        assert name in source
    assert len(source.splitlines()) < 80


def test_split_modules_stay_below_original_monolith_sizes() -> None:
    limits = {
        "application/workflow_runtime.py": 300,
        "presentation/pages/studio.py": 300,
        "presentation/pages/enterprise.py": 450,
        "presentation/pages/network.py": 450,
        "presentation/pages/tools.py": 80,
        "application/command_runtime_professional.py": 100,
        "infrastructure/capture/protocol_application.py": 450,
        "infrastructure/capture/packet_analysis.py": 650,
    }
    for relative, maximum in limits.items():
        path = SRC / relative
        assert len(path.read_text(encoding="utf-8").splitlines()) <= maximum, relative


def test_no_chinese_comments_or_python_docstrings_remain() -> None:
    cjk = re.compile(r"[\u4e00-\u9fff]")
    failures: list[str] = []
    for path in ROOT.rglob("*.py"):
        if any(part in {".venv", "build", "dist", "__pycache__"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT and cjk.search(token.string):
                failures.append(f"{path}:{token.start[0]} comment")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc and cjk.search(doc):
                    failures.append(f"{path}:{getattr(node, 'lineno', 1)} docstring")
    assert not failures, failures
