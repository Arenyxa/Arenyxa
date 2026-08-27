from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class Command:
    name: str
    argv: tuple[str, ...]
    timeout: int
    required_local: bool = True
    available: bool = True
    unavailable_reason: str = ""


def _run(command: Command, env: dict[str, str]) -> dict[str, Any]:
    if not command.available:
        return {
            "name": command.name,
            "status": "NOT_EXECUTED",
            "required_local": command.required_local,
            "reason": command.unavailable_reason,
            "command": list(command.argv),
            "return_code": None,
            "duration_seconds": 0.0,
        }
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command.argv,
            cwd=ROOT,
            env=env,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=command.timeout,
        )
        output = completed.stdout
        code = int(completed.returncode)
        status = "PASS" if code == 0 else "FAIL"
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout or ""
        output = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        output += "\nTIMEOUT"
        code = 124
        status = "FAIL"
    return {
        "name": command.name,
        "status": status,
        "required_local": command.required_local,
        "command": list(command.argv),
        "return_code": code,
        "duration_seconds": round(time.monotonic() - started, 3),
        "output_sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
        "output_tail": output[-20000:],
    }


def _atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _tool(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _commands(env: dict[str, str]) -> list[Command]:
    py = sys.executable
    is_windows = os.name == "nt"
    has_tshark = shutil.which("tshark") is not None
    has_pg = bool(env.get("ARENYXA_POSTGRES_TEST_DSN", "").strip())
    has_ruff_mypy = _tool("ruff") and _tool("mypy")
    return [
        Command("compileall", (py, "-m", "compileall", "-q", "src/arenyxa", "scripts", "tests"), 240),
        Command(
            "static_quality_gate",
            (py, "scripts/static_quality_gate.py"),
            900,
            required_local=False,
            available=has_ruff_mypy,
            unavailable_reason="ruff and/or mypy are not installed in this runtime",
        ),
        Command("python38_grammar", (py, "scripts/check_python38_grammar.py"), 240),
        Command("v81_identity", (py, "scripts/verify_v81_release_identity.py"), 180),
        Command("phase6_gate", (py, "scripts/v8_phase6_gate.py"), 900),
        Command("full_pytest", (py, "-m", "pytest", "-q", "--disable-warnings", "--maxfail=1"), 2400),
        Command("phase0_integrity", (py, "scripts/phase0_gate.py", "--skip-pytest", "--skip-static"), 600),
        Command("github_publication", (py, "scripts/github_publication_gate.py", "--allow-local-artifacts"), 300),
        Command(
            "tshark_protocol_differential",
            (py, "-m", "pytest", "-q", "tests/test_v71_protocol_differential_tshark.py"),
            600,
            required_local=False,
            available=has_tshark,
            unavailable_reason="tshark is not installed",
        ),
        Command(
            "postgresql_32_worker",
            (py, "scripts/postgresql_32_worker_gate.py", "--dsn", env.get("ARENYXA_POSTGRES_TEST_DSN", ""), "--report", "POSTGRESQL_32_WORKER_GATE.json"),
            600,
            required_local=False,
            available=has_pg,
            unavailable_reason="ARENYXA_POSTGRES_TEST_DSN is not configured",
        ),
        Command(
            "windows_native",
            (py, "scripts/windows_native_qualification.py", "--report", "WINDOWS_NATIVE_QUALIFICATION.json"),
            900,
            required_local=False,
            available=is_windows,
            unavailable_reason="current execution host is not Windows; no Windows VM/hypervisor is available",
        ),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Arenyxa v8.1 final release validation and evidence collector")
    parser.add_argument("--report", type=Path, default=ROOT / "V8_TEST_EVIDENCE.json")
    args = parser.parse_args(argv)
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    started = datetime.now(UTC).isoformat(timespec="seconds")
    results: list[dict[str, Any]] = []
    for command in _commands(env):
        print(f"=== {command.name} ===", flush=True)
        result = _run(command, env)
        results.append(result)
        if result.get("output_tail"):
            print(result["output_tail"], flush=True)
        print(result["status"], flush=True)
    required = [item for item in results if item.get("required_local")]
    required_passed = bool(required) and all(item.get("status") == "PASS" for item in required)
    external = [item for item in results if not item.get("required_local")]
    external_complete = all(item.get("status") == "PASS" for item in external)
    payload = {
        "schema": "arenyxa.v8-test-evidence/v2",
        "version": "8.1",
        "package_version": "8.1.0",
        "started_at": started,
        "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "full": True,
        "python": sys.version,
        "platform": platform.platform(),
        "windows_vm_attempt": {
            "qemu_system_x86_64": shutil.which("qemu-system-x86_64"),
            "wine": shutil.which("wine"),
            "powershell": shutil.which("pwsh") or shutil.which("powershell"),
            "kvm_device": Path("/dev/kvm").exists(),
            "status": "AVAILABLE" if (shutil.which("qemu-system-x86_64") and Path("/dev/kvm").exists()) else "NOT_AVAILABLE",
        },
        "local_engineering_passed": required_passed,
        "external_certification_complete": external_complete,
        "passed": required_passed,
        "results": results,
    }
    _atomic(args.report.resolve(), payload)
    print(f"Evidence: {args.report.resolve()}")
    print("V8.1 LOCAL ENGINEERING: PASS" if required_passed else "V8.1 LOCAL ENGINEERING: FAIL")
    print("EXTERNAL CERTIFICATION: PASS" if external_complete else "EXTERNAL CERTIFICATION: PARTIAL / NOT EXECUTED")
    return 0 if required_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
