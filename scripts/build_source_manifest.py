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

# Exact local execution records: preserve originals without shipping machine paths.
PRESERVED_ROOT_FILES = {
    "release_baseline_audit.md", "phase0_baseline_record.md",
    "arenxya_v0.1_release_execution_plan.md", "release_execution_checklist.md",
    "release_fix_plan.md", "v0.1_source_baseline.md", "phase6_source_integrity.txt", "gui-smoke.png",
    "runtime_stabilization_report.md", "release_test_report.md", "p99_final_validation_report.md",
    "real_gui_acceptance_report.md", "build_release_report.md", "clean_install_validation_report.md",
    "final_release_report.md", "github_release_preparation_report.md", "public_source_sanitization_report.md",
    "gui_automation_limitation_report.md", "version_migration_report.md", "documentation_release_report.md",
}


def is_preserved_local_artifact(relative: Path) -> bool:
    """Classify local evidence/tools/backups without deleting their original files."""
    parts = tuple(part.casefold() for part in relative.parts)
    if not parts:
        return False
    if len(parts) == 1 and parts[0] in PRESERVED_ROOT_FILES:
        return True
    if parts[0] in {".release", "release", "evidence", "handoff_notes"}:
        return True
    if parts[0].startswith(("p99_", "audit_out_")):
        return True
    return any(".before_" in part or part.endswith((".bak", ".backup", ".orig", ".pre_abg"))
               for part in parts)


def is_generated_or_ephemeral(relative: Path) -> bool:
    if is_preserved_local_artifact(relative):
        return True
    # Local AI/editor state must never enter source manifests or source archives.
    if any(part.startswith(".aider") for part in relative.parts):
        return True
    if relative.as_posix() in EXCLUDED_FILES:
        return True
    if relative.name.startswith(".coverage."):
        return True
    if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
        return True
    return relative.suffix in {".pyc", ".pyo"}


def iter_source_files(root: Path):
    """Prune excluded roots before traversal, including large local tool trees."""
    for directory, names, files in os.walk(root):
        parent = Path(directory)
        names[:] = sorted(name for name in names
                          if not is_generated_or_ephemeral((parent / name).relative_to(root)))
        for name in sorted(files):
            path = parent / name
            if path.is_file() and not is_generated_or_ephemeral(path.relative_to(root)):
                yield path


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
    for path in sorted(iter_source_files(root)):
        relative = path.relative_to(root)
        rows.append(f"{sha256(path)}  {relative.as_posix()}")
    atomic_write_text(destination, "\n".join(rows) + "\n")
    print(f"Source manifest: {destination} ({len(rows)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
