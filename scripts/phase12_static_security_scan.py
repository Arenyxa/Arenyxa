from __future__ import annotations

import ast
import re
from pathlib import Path


NEW_SECURITY_SENSITIVE_MODULES = (
    "src/arenyxa/application/web_intelligence.py",
    "src/arenyxa/architecture_contracts.py",
    "src/arenyxa/application/reliability.py",
    "src/arenyxa/application/workflow_test_lab.py",
    "src/arenyxa/enterprise/identity.py",
    "src/arenyxa/enterprise/enrollment.py",
    "src/arenyxa/enterprise/coordinator.py",
    "src/arenyxa/enterprise/governance.py",
    "src/arenyxa/enterprise/distributed.py",
    "src/arenyxa/enterprise/server_api.py",
    "src/arenyxa/enterprise/migration.py",
    "src/arenyxa/release_hardening.py",
)
FORBIDDEN_IMPORT_ROOTS = {"pickle", "marshal", "ctypes"}
FORBIDDEN_CALLS = {"eval", "exec", "os.system", "subprocess.run", "subprocess.Popen", "subprocess.call"}
SECRET_LITERAL = re.compile(r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{16,}|Bearer\s+[A-Za-z0-9._~+/-]{20,})")


def call_name(node: ast.Call) -> str:
    current = node.func
    parts: list[str] = []
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings: list[str] = []
    for relative in NEW_SECURITY_SENSITIVE_MODULES:
        path = root / relative
        source = path.read_text(encoding="utf-8")
        if SECRET_LITERAL.search(source):
            findings.append(f"{relative}: secret/private-key-like literal")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in FORBIDDEN_IMPORT_ROOTS:
                        findings.append(f"{relative}:{node.lineno}: forbidden import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".", 1)[0] in FORBIDDEN_IMPORT_ROOTS:
                    findings.append(f"{relative}:{node.lineno}: forbidden import {node.module}")
            elif isinstance(node, ast.Call):
                name = call_name(node)
                if name in FORBIDDEN_CALLS:
                    findings.append(f"{relative}:{node.lineno}: forbidden call {name}")
    if findings:
        print("Phase 1-12 static security scan: FAIL")
        for item in findings:
            print("- " + item)
        return 1
    print("Phase 1-12 static security scan: PASS")
    print("- reviewed architecture/web-intelligence/reliability/enterprise/distributed/release modules contain no eval/exec/pickle/marshal/ctypes/subprocess execution")
    print("- no private-key/Bearer-token-like hardcoded literals detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
