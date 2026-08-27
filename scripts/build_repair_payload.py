from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def is_critical(relative: str) -> bool:
    lowered = relative.casefold().replace("\\", "/")
    name = Path(lowered).name
    return (
        lowered == "arenyxa.exe"
        or lowered.startswith("_internal/arenyxa/")
        or name.startswith("python3") and name.endswith(".dll")
        or name in {"base_library.zip"}
        or (name.startswith(("qt5", "qt6")) and name.endswith(".dll"))
        or "pyside6" in lowered
        or "pyside2" in lowered
        or "shiboken6" in lowered
        or "shiboken2" in lowered
    )


def main() -> int:
    project = Path(__file__).resolve().parents[1]
    dist = project / "dist" / "Arenyxa"
    if not dist.exists():
        print(f"Distribution not found: {dist}", file=sys.stderr)
        return 2

    repair = dist / "repair"
    repair.mkdir(parents=True, exist_ok=True)
    payload = repair / "recovery_payload.zip"
    manifest = repair / "install_manifest.json"
    payload.unlink(missing_ok=True)
    manifest.unlink(missing_ok=True)

    files: dict[str, dict[str, object]] = {}
    candidates = [path for path in dist.rglob("*") if path.is_file() and repair not in path.parents]
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(candidates):
            relative = path.relative_to(dist).as_posix()
            files[relative] = {"sha256": digest(path), "size": path.stat().st_size}
            archive.write(path, relative)

    critical_files = [relative for relative in files if is_critical(relative)]
    obj = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "product": "Arenyxa",
        "files": files,
        "critical_files": critical_files,
        "recovery_payload": {
            "name": payload.name,
            "sha256": digest(payload),
            "size": payload.stat().st_size,
        },
    }
    manifest.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Repair manifest: {manifest}")
    print(f"Critical startup files: {len(critical_files)}")
    print(f"Recovery payload: {payload} ({payload.stat().st_size / 1024 / 1024:.1f} MiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
