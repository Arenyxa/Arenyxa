from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET_DIR = ROOT / "tests" / "fuzz"
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))


def _corpus() -> list[bytes]:
    seeds = [
        b"", b"\x00", b"\xff" * 8, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
        bytes.fromhex("160301002e0100002a0303") + b"A" * 40,
        b'{"ok":true}', b'{"a":1,"a":2}', b"[1,2,3]", b"not-json",
        bytes(range(256)), b"\x45\x00" + b"\x00" * 62,
    ]
    # Deterministic byte sequences make the gate stable in CI while covering
    # lengths, high-bit bytes, embedded NULs, and parser boundary values.
    for index in range(36):
        digest = hashlib.sha512(f"arenyxa-fuzz-smoke-{index}".encode("ascii")).digest()
        length = (index * 37) % 1025
        material = bytearray()
        counter = 0
        while len(material) < length:
            material.extend(hashlib.sha512(digest + counter.to_bytes(4, "big")).digest())
            counter += 1
        seeds.append(bytes(material[:length]))
    return seeds


def _load_target(path: Path) -> Callable[[bytes], object]:
    spec = importlib.util.spec_from_file_location(f"arenyxa_fuzz_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load fuzz target: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = getattr(module, "fuzz", None)
    if not callable(target):
        raise TypeError(f"fuzz target has no callable fuzz(data): {path}")
    return target


def main() -> int:
    corpus = _corpus()
    targets = sorted(TARGET_DIR.glob("fuzz_*.py"))
    failures: list[dict[str, str | int]] = []
    executed = 0
    per_target: dict[str, int] = {}
    for path in targets:
        try:
            target = _load_target(path)
        except Exception as exc:  # noqa: BLE001 - isolate and report one invalid target
            failures.append({"target": path.name, "case": -1, "error": f"load: {type(exc).__name__}: {exc}"})
            continue
        target_cases = 0
        for index, payload in enumerate(corpus):
            try:
                target(payload)
            except Exception as exc:  # noqa: BLE001 - fuzz target failures are retained as evidence
                failures.append({"target": path.name, "case": index, "error": f"{type(exc).__name__}: {exc}"})
                if len(failures) >= 25:
                    break
            executed += 1
            target_cases += 1
        per_target[path.name] = target_cases
        if len(failures) >= 25:
            break
    result = {
        "schema": "arenyxa.fuzz-smoke-gate/v2",
        "healthy": not failures and bool(targets),
        "mode": "deterministic-smoke",
        "targets": len(targets),
        "corpus_cases": len(corpus),
        "executed_cases": executed,
        "per_target": per_target,
        "failures": failures,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
