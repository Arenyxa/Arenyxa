from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / "src" / "arenyxa" / "presentation" / "pages"


def _button_target(target: ast.AST) -> str | None:
    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
        return "self." + target.attr
    if isinstance(target, ast.Name):
        return target.id
    return None


def _button_signal_target(call: ast.Call) -> str | None:
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "connect":
        return None
    signal = call.func.value
    if not isinstance(signal, ast.Attribute) or signal.attr not in {"clicked", "toggled"}:
        return None
    return _button_target(signal.value)


def main() -> int:
    failures: list[str] = []
    declared_total = 0
    for path in sorted(PAGES.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

                                                                                                   
                                                                                                    
                                                                                            
                                   
        self_declared: set[str] = set()
        self_connected: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Name) and func.id == "QPushButton":
                    for target in node.targets:
                        name = _button_target(target)
                        if name and name.startswith("self."):
                            self_declared.add(name)
            if isinstance(node, ast.Call):
                name = _button_signal_target(node)
                if name and name.startswith("self."):
                    self_connected.add(name)
        declared_total += len(self_declared)
        missing_self = sorted(self_declared - self_connected)
        if missing_self:
            failures.append(f"{path.relative_to(ROOT)}: {', '.join(missing_self)}")

        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            local_declared: set[str] = set()
            local_connected: set[str] = set()
            for node in ast.walk(function):
                if node is not function and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    continue
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    func = node.value.func
                    if isinstance(func, ast.Name) and func.id == "QPushButton":
                        for target in node.targets:
                            name = _button_target(target)
                            if name and not name.startswith("self."):
                                local_declared.add(name)
                if isinstance(node, ast.Call):
                    name = _button_signal_target(node)
                    if name and not name.startswith("self."):
                        local_connected.add(name)
            declared_total += len(local_declared)
            missing_local = sorted(local_declared - local_connected)
            if missing_local:
                failures.append(
                    f"{path.relative_to(ROOT)}::{function.name}: " + ", ".join(missing_local)
                )
    if failures:
        print("UI button connection contract: FAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"UI button connection contract: PASS ({declared_total} page QPushButtons wired, including local dialog actions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
