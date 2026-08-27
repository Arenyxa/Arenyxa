from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path


EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "installer_output",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".hypothesis",
    ".tox",
    ".nox",
    "htmlcov",
    "work",
}
EXCLUDED_FILES = {
    "SOURCE_MANIFEST.sha256",
    ".coverage",
    "coverage.json",
    "coverage.xml",
    "arenyxa_startup_error.log",
}


def is_generated_or_ephemeral(relative: Path) -> bool:
    if relative.as_posix() in EXCLUDED_FILES:
        return True
    if relative.name.startswith(".coverage."):
        return True
    if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
        return True
    return relative.suffix in {".pyc", ".pyo"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(raw_temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    destination = root / "SOURCE_MANIFEST.sha256"
    rows: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if is_generated_or_ephemeral(relative):
            continue
        rows.append(f"{sha256(path)}  {relative.as_posix()}")
    atomic_write_text(destination, "\n".join(rows) + "\n")
    print(f"Source manifest: {destination} ({len(rows)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
