from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fsync_file(path: Path) -> None:
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_json_temp(parent: Path, target_name: str, payload: dict[str, object]) -> Path:
    fd, raw_temp = tempfile.mkstemp(prefix=f".{target_name}.", suffix=".tmp", dir=parent)
    temp = Path(raw_temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        return temp
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def _package_candidates(package: Path) -> Iterable[Path]:
    for path in package.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(package).as_posix()
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if relative in {"resources/repair_seed.zip", "resources/repair_manifest.json"}:
            continue
        yield path


def build_seed(project: Path, *, win7: bool) -> tuple[Path, Path, int]:
    if win7:
        package = project / "legacy" / "win7" / "src" / "arenyxa"
        resources = package / "resources"
        extra_candidates = [project / "legacy" / "win7" / "LEGACY_RUNTIME.json"]
        runtime = "win7-frozen"
    else:
        package = project / "src" / "arenyxa"
        resources = package / "resources"
        extra_candidates = [project / "pyproject.toml", project / "requirements.txt"]
        runtime = "modern"
    if not package.is_dir():
        raise FileNotFoundError(f"Arenyxa package is missing: {package}")

    resources.mkdir(parents=True, exist_ok=True)
    seed = resources / "repair_seed.zip"
    manifest_path = resources / "repair_manifest.json"
    candidates = sorted({*list(_package_candidates(package)), *(path for path in extra_candidates if path.is_file())})
    files = {path.relative_to(project).as_posix(): sha256(path) for path in candidates}
    embedded: dict[str, object] = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "product": "Arenyxa",
        "runtime": runtime,
        "files": files,
    }

    seed_fd, raw_seed_temp = tempfile.mkstemp(prefix=".repair_seed.", suffix=".zip.tmp", dir=resources)
    os.close(seed_fd)
    seed_temp = Path(raw_seed_temp)
    manifest_temp: Path | None = None
    try:
        with zipfile.ZipFile(seed_temp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            archive.writestr("MANIFEST.json", json.dumps(embedded, ensure_ascii=False, indent=2))
            for path in candidates:
                archive.write(path, path.relative_to(project).as_posix())
        with zipfile.ZipFile(seed_temp, "r") as archive:
            bad = archive.testzip()
            if bad is not None:
                raise RuntimeError(f"Generated repair seed failed CRC validation: {bad}")
            archive_manifest = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
            if dict(archive_manifest.get("files", {})) != files:
                raise RuntimeError("Generated repair seed manifest did not round-trip")
        _fsync_file(seed_temp)

        release_manifest = dict(embedded)
        release_manifest["seed_sha256"] = sha256(seed_temp)
        release_manifest["seed_size"] = seed_temp.stat().st_size
        manifest_temp = _write_json_temp(resources, manifest_path.name, release_manifest)
        os.replace(seed_temp, seed)
        os.replace(manifest_temp, manifest_path)
        manifest_temp = None
    finally:
        seed_temp.unlink(missing_ok=True)
        if manifest_temp is not None:
            manifest_temp.unlink(missing_ok=True)
    return manifest_path, seed, len(files)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Arenyxa source-mode repair seed for one runtime lane.")
    parser.add_argument("--win7", action="store_true", help="build the frozen Windows 7 source repair seed")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    manifest, seed, count = build_seed(project, win7=bool(args.win7))
    print(f"Source repair manifest: {manifest}")
    print(f"Source repair seed: {seed} ({seed.stat().st_size / 1024:.1f} KiB, {count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
