from __future__ import annotations

"""Verify the immutable-source invariants required by Roadmap Phase 0.

This verifier is intentionally standard-library-only so it can run before the
full desktop dependency set is available.  It validates the source manifest as
an exact inventory, the embedded Repair Seed as an internally consistent
recovery image, release identity, and the absence of build/cache artefacts.
"""

import argparse
import hashlib
import json
import re
import sys
import zipfile
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
REPAIR_GENERATED = {
    "src/arenyxa/resources/repair_seed.zip",
    "src/arenyxa/resources/repair_manifest.json",
}
LOCAL_ARTIFACT_PARTS = {".git", ".venv", "build", "dist", "installer_output"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_manifest_excluded(relative: Path) -> bool:
    if relative.as_posix() in EXCLUDED_FILES:
        return True
    if relative.name.startswith(".coverage."):
        return True
    if any(part.startswith(".aider") for part in relative.parts):
        return True
    if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
        return True
    return relative.suffix in {".pyc", ".pyo"}


def source_inventory(root: Path) -> set[str]:
    inventory: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if is_manifest_excluded(relative):
            continue
        inventory.add(relative.as_posix())
    return inventory


def verify_source_manifest(root: Path) -> dict[str, object]:
    manifest = root / "SOURCE_MANIFEST.sha256"
    if not manifest.is_file():
        raise RuntimeError("SOURCE_MANIFEST.sha256 is missing")

    rows = [line.strip() for line in manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise RuntimeError("SOURCE_MANIFEST.sha256 is empty")

    seen: dict[str, str] = {}
    for index, row in enumerate(rows, 1):
        try:
            expected, relative = row.split("  ", 1)
        except ValueError as exc:
            raise RuntimeError(f"Malformed source manifest row {index}") from exc
        if relative in seen:
            raise RuntimeError(f"Duplicate source manifest entry: {relative}")
        if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
            raise RuntimeError(f"Invalid SHA-256 at source manifest row {index}")
        path = root / relative
        if not path.is_file():
            raise RuntimeError(f"Manifest references missing file: {relative}")
        actual = sha256(path)
        if actual != expected:
            raise RuntimeError(f"Source manifest hash mismatch: {relative}")
        seen[relative] = expected

    expected_inventory = source_inventory(root)
    actual_inventory = set(seen)
    untracked = sorted(expected_inventory - actual_inventory)
    stale = sorted(actual_inventory - expected_inventory)
    if untracked or stale:
        parts = []
        if untracked:
            parts.append("untracked=" + ", ".join(untracked[:10]))
        if stale:
            parts.append("stale=" + ", ".join(stale[:10]))
        raise RuntimeError("Source manifest is not an exact inventory: " + "; ".join(parts))

    return {"files": len(seen), "sha256": sha256(manifest)}


def verify_repair_seed(root: Path) -> dict[str, object]:
    resources = root / "src" / "arenyxa" / "resources"
    seed = resources / "repair_seed.zip"
    release_manifest_path = resources / "repair_manifest.json"
    if not seed.is_file() or not release_manifest_path.is_file():
        raise RuntimeError("Repair Seed or repair_manifest.json is missing")

    release_manifest = json.loads(release_manifest_path.read_text(encoding="utf-8"))
    if release_manifest.get("product") != "Arenyxa":
        raise RuntimeError("Repair manifest product identity mismatch")
    if release_manifest.get("seed_sha256") != sha256(seed):
        raise RuntimeError("Repair Seed SHA-256 mismatch")
    if int(release_manifest.get("seed_size", -1)) != seed.stat().st_size:
        raise RuntimeError("Repair Seed size mismatch")

    with zipfile.ZipFile(seed, "r") as archive:
        bad = archive.testzip()
        if bad is not None:
            raise RuntimeError(f"Repair Seed CRC failure: {bad}")
        names = archive.namelist()
        if "MANIFEST.json" not in names:
            raise RuntimeError("Repair Seed MANIFEST.json is missing")
        embedded = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
        files = embedded.get("files")
        if not isinstance(files, dict) or not files:
            raise RuntimeError("Repair Seed embedded file inventory is invalid")
        if embedded.get("product") != "Arenyxa":
            raise RuntimeError("Repair Seed product identity mismatch")
        if files != release_manifest.get("files"):
            raise RuntimeError("Repair Seed and external repair manifest inventories differ")

        expected_archive_names = {"MANIFEST.json", *files.keys()}
        if set(names) != expected_archive_names:
            raise RuntimeError("Repair Seed ZIP entries do not exactly match its manifest")

        for relative, expected_hash in files.items():
            if not isinstance(relative, str) or not isinstance(expected_hash, str):
                raise RuntimeError("Repair Seed contains malformed file metadata")
            payload = archive.read(relative)
            actual_hash = hashlib.sha256(payload).hexdigest()
            if actual_hash != expected_hash:
                raise RuntimeError(f"Repair Seed embedded hash mismatch: {relative}")
            current = root / relative
            if not current.is_file():
                raise RuntimeError(f"Repair Seed references missing current file: {relative}")
            if sha256(current) != expected_hash:
                raise RuntimeError(f"Repair Seed is stale relative to source: {relative}")

    return {"files": len(files), "size": seed.stat().st_size, "sha256": sha256(seed)}


def verify_release_identity(root: Path) -> dict[str, str]:
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    project_match = re.search(r"(?ms)^\[project\]\s*$.*?^version\s*=\s*[\"\']([^\"\']+)[\"\']", pyproject)
    if project_match is None:
        raise RuntimeError("Unable to read [project] version from pyproject.toml")
    package_version = project_match.group(1)
    if package_version != "8.1.0":
        raise RuntimeError(f"Unexpected package version: {package_version}")

    namespace = (root / "src" / "arenyxa" / "__init__.py").read_text(encoding="utf-8")
    required = ('__version__ = "8.1"', '__package_version__ = "8.1.0"', '__compat_version__ = "6.8.0"')
    for token in required:
        if token not in namespace:
            raise RuntimeError(f"Release identity token missing: {token}")
    return {"runtime": "8.1", "package": "8.1.0", "compat": "6.8.0"}


def verify_clean_tree(root: Path, *, allow_local_artifacts: bool = False) -> dict[str, object]:
    forbidden: list[str] = []
    ignored_local_roots: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        local_parts = set(relative.parts) & LOCAL_ARTIFACT_PARTS
        if allow_local_artifacts and local_parts:
            ignored_local_roots.update(local_parts)
            continue
        if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            forbidden.append(relative.as_posix())
            continue
        if path.is_file() and (path.suffix in {".pyc", ".pyo"} or path.name.startswith(".coverage")):
            forbidden.append(relative.as_posix())
    if forbidden:
        raise RuntimeError("Ephemeral/build artefacts present: " + ", ".join(sorted(forbidden)[:20]))
    return {"forbidden_artifacts": 0, "ignored_local_roots": sorted(ignored_local_roots)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Arenyxa v8.1 release baseline invariants")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--allow-local-artifacts",
        action="store_true",
        help="ignore .git/.venv/build/dist roots while still rejecting source-tree caches",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    checks = {
        "release_identity": verify_release_identity(root),
        "repair_seed": verify_repair_seed(root),
        "source_manifest": verify_source_manifest(root),
        "clean_tree": verify_clean_tree(root, allow_local_artifacts=args.allow_local_artifacts),
    }
    payload = {"status": "PASS", "phase": 0, "root": str(root), "checks": checks}
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("Arenyxa Phase 0 baseline verification: PASS")
        for name, result in checks.items():
            print(f"- {name}: {result}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Arenyxa Phase 0 baseline verification: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
