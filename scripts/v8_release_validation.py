from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class ValidationCommand:
    name: str
    arguments: tuple[str, ...]
    timeout_seconds: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _commands(python: str, *, full: bool) -> list[ValidationCommand]:
    commands = [
        ValidationCommand("compileall", (python, "-m", "compileall", "-q", "src", "scripts"), 180),
        ValidationCommand(
            "ruff_critical",
            (
                python,
                "-m",
                "ruff",
                "check",
                "--select",
                "E9,F63,F7,F82",
                "src/arenyxa",
                "scripts",
                "tests",
            ),
            180,
        ),
        ValidationCommand("architecture", (python, "scripts/architecture_debt_gate.py"), 180),
        ValidationCommand("version", (python, "scripts/verify_v81_release_identity.py"), 120),
        ValidationCommand("cli_runtime", (python, "scripts/verify_cli_contract.py"), 180),
        ValidationCommand("ui_wiring", (python, "scripts/verify_ui_button_connections.py"), 180),
        ValidationCommand(
            "v8_integration",
            (python, "-m", "pytest", "-q", "tests/test_v80_platform_control_plane.py"),
            300,
        ),
        ValidationCommand("reliability", (python, "scripts/test_reliability_gate.py"), 600),
    ]
    if full:
        commands.append(
            ValidationCommand("full_pytest", (python, "-m", "pytest", "-q"), 1800)
        )
    return commands


def _run(command: ValidationCommand, environment: dict[str, str]) -> dict[str, object]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command.arguments,
            cwd=ROOT,
            env=environment,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=command.timeout_seconds,
        )
        return_code = int(completed.returncode)
        output = completed.stdout
    except subprocess.TimeoutExpired as exc:
        return_code = 124
        raw_output = exc.stdout or ""
        output = raw_output.decode("utf-8", "replace") if isinstance(raw_output, bytes) else raw_output
        output += "\nVALIDATION TIMEOUT"
    duration = round(time.monotonic() - started, 3)
    return {
        "name": command.name,
        "command": list(command.arguments),
        "timeout_seconds": command.timeout_seconds,
        "duration_seconds": duration,
        "return_code": return_code,
        "passed": return_code == 0,
        "output_sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
        "output_tail": output[-16_000:],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute and retain reproducible Arenyxa v8.1 validation evidence."
    )
    parser.add_argument("--full", action="store_true", help="include the complete pytest regression suite")
    parser.add_argument("--report", type=Path, default=ROOT / "V8_TEST_EVIDENCE.json")
    args = parser.parse_args(argv)
    environment = dict(os.environ)
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + environment.get("PYTHONPATH", "")
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    results: list[dict[str, object]] = []
    for command in _commands(sys.executable, full=bool(args.full)):
        print(f"=== {command.name} ===", flush=True)
        result = _run(command, environment)
        results.append(result)
        print(result["output_tail"], flush=True)
        print("PASS" if result["passed"] else "FAIL", flush=True)
    report: dict[str, object] = {
        "schema": "arenyxa.v8-test-evidence/v1",
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "full": bool(args.full),
        "python": sys.version,
        "platform": platform.platform(),
        "source_manifest_sha256": (
            _sha256(ROOT / "SOURCE_MANIFEST.sha256")
            if (ROOT / "SOURCE_MANIFEST.sha256").is_file()
            else None
        ),
        "passed": bool(results) and all(bool(item["passed"]) for item in results),
        "results": results,
    }
    _atomic_json(args.report.resolve(), report)
    print(f"Evidence: {args.report.resolve()}")
    print("V8 RELEASE VALIDATION: PASS" if report["passed"] else "V8 RELEASE VALIDATION: FAIL")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
