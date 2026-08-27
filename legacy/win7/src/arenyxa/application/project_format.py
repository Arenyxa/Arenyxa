from __future__ import annotations

from arenyxa.compat import path_is_relative_to

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from pathlib import Path
from typing import Any

from arenyxa import __version__
from arenyxa.branding import LEGACY_PROJECT_FORMATS, PROJECT_FORMAT
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.atomic_io import fsync_existing_file

ALLOWED_ROOTS = {
    "workflows",
    "selectors",
    "schemas",
    "scripts",
    "tests",
    "schedules",
    "visualizations",
    "snapshots",
}
MAX_ARCHIVE_ENTRIES = 20_000
MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024


@dataclass(slots=True)
class ProjectManifest:
    name: str
    version: str = "1.0.0"
    format: str = PROJECT_FORMAT
    created_at: str = field(default_factory=utc_now)
    app_version: str = __version__
    plugin_dependencies: list[dict[str, str]] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    contains_secrets: bool = False


class ArenyxaProjectService:
    def pack(self, source: Path, destination: Path, manifest: ProjectManifest) -> Path:
        source = source.resolve()
        destination = destination.expanduser()
        destination_resolved = destination.resolve()
        files: list[tuple[Path, str]] = []
        for path in source.rglob("*"):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if path.is_symlink() or not path_is_relative_to(resolved, source):
                continue
                                                                                          
                                                                                      
            if resolved == destination_resolved:
                continue
            relative = path.relative_to(source).as_posix()
            if relative == "manifest.json":
                continue
            root = relative.split("/", 1)[0]
            if root not in ALLOWED_ROOTS:
                continue
            if "secret" in relative.lower() or path.suffix.lower() in {".pem", ".key", ".pfx"}:
                continue
            files.append((path, relative))
            if len(files) > MAX_ARCHIVE_ENTRIES - 1:                                       
                raise ArenyxaError("PROJECT_ARCHIVE_LIMIT", "项目源文件数量超过安全上限。", domain="PROJECT")
        total_size = sum(path.stat().st_size for path, _relative in files)
        if total_size > MAX_UNCOMPRESSED_BYTES:
            raise ArenyxaError("PROJECT_ARCHIVE_LIMIT", "项目源文件总大小超过安全上限。", domain="PROJECT")
        manifest.files = {relative: self._hash(path) for path, relative in files}
        manifest.contains_secrets = False

        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name or 'project'}.packing-", suffix=".tmp", dir=destination.parent
        )
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                archive.writestr("manifest.json", json.dumps(asdict(manifest), ensure_ascii=False, indent=2))
                for path, relative in sorted(files, key=lambda item: item[1]):
                    archive.write(path, relative)
                                                                                                 
                                                                                        
            self.validate(temporary)
            fsync_existing_file(temporary)
            os.replace(temporary, destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return destination

    def validate(self, package: Path) -> ProjectManifest:
        with zipfile.ZipFile(package) as archive:
            names = archive.namelist()
                                                                                  
                                                                                      
            if len(names) != len(set(names)):
                raise ArenyxaError(
                    "PROJECT_DUPLICATE_ENTRY", "项目包包含重复 ZIP 条目，拒绝加载。", domain="PROJECT"
                )
            self._validate_names(names)
            if len(names) > MAX_ARCHIVE_ENTRIES:
                raise ArenyxaError("PROJECT_ARCHIVE_LIMIT", "项目包文件数量超过安全上限。", domain="PROJECT")
            infos = archive.infolist()
            if sum(info.file_size for info in infos) > MAX_UNCOMPRESSED_BYTES:
                raise ArenyxaError(
                    "PROJECT_ARCHIVE_LIMIT", "项目包解压后大小超过安全上限。", domain="PROJECT"
                )
            for info in infos:
                normalized = info.filename.replace("\\", "/")
                if info.flag_bits & 0x1:
                    raise ArenyxaError(
                        "PROJECT_ENCRYPTED_ENTRY", f"项目包不允许加密 ZIP 条目：{normalized}", domain="PROJECT"
                    )
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if (unix_mode & 0o170000) == 0o120000:
                    raise ArenyxaError(
                        "PROJECT_SYMLINK_ENTRY", f"项目包包含符号链接：{normalized}", domain="PROJECT"
                    )
                if normalized.endswith("/") or normalized == "manifest.json":
                    continue
                root = normalized.split("/", 1)[0]
                if root not in ALLOWED_ROOTS:
                    raise ArenyxaError(
                        "PROJECT_ROOT_UNSUPPORTED",
                        f"项目包文件位于未支持的根目录：{normalized}",
                        domain="PROJECT",
                    )
            if "manifest.json" not in names:
                raise ArenyxaError("PROJECT_MANIFEST_MISSING", "项目包缺少 manifest.json。", domain="PROJECT")
            manifest_info = archive.getinfo("manifest.json")
            if manifest_info.file_size > MAX_MANIFEST_BYTES:
                raise ArenyxaError("PROJECT_MANIFEST_INVALID", "项目 manifest.json 超过安全大小上限。", domain="PROJECT")
            try:
                raw_value: Any = json.loads(archive.read("manifest.json"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ArenyxaError("PROJECT_MANIFEST_INVALID", "项目 manifest.json 无法解析。", domain="PROJECT") from exc
            if not isinstance(raw_value, dict):
                raise ArenyxaError("PROJECT_MANIFEST_INVALID", "项目 manifest.json 根节点必须是 JSON object。", domain="PROJECT")
            allowed_fields = set(ProjectManifest.__dataclass_fields__)
            if set(raw_value) - allowed_fields:
                raise ArenyxaError("PROJECT_MANIFEST_INVALID", "项目 manifest.json 包含未知字段。", domain="PROJECT")
            try:
                manifest = ProjectManifest(**raw_value)
            except (TypeError, ValueError) as exc:
                raise ArenyxaError("PROJECT_MANIFEST_INVALID", "项目 manifest.json 字段类型无效。", domain="PROJECT") from exc
            for field_name in ("name", "version", "format", "created_at", "app_version"):
                if not isinstance(getattr(manifest, field_name), str):
                    raise ArenyxaError(
                        "PROJECT_MANIFEST_INVALID",
                        f"项目 manifest.json 的 {field_name} 必须是字符串。",
                        domain="PROJECT",
                    )
            if not manifest.name.strip():
                raise ArenyxaError("PROJECT_MANIFEST_INVALID", "项目名称不能为空。", domain="PROJECT")
            if not isinstance(manifest.files, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in manifest.files.items()):
                raise ArenyxaError("PROJECT_MANIFEST_INVALID", "项目文件完整性清单格式无效。", domain="PROJECT")
            if not isinstance(manifest.plugin_dependencies, list) or not all(
                isinstance(item, dict)
                and all(isinstance(key, str) and isinstance(value, str) for key, value in item.items())
                for item in manifest.plugin_dependencies
            ):
                raise ArenyxaError("PROJECT_MANIFEST_INVALID", "插件依赖清单格式无效。", domain="PROJECT")
            if not isinstance(manifest.contains_secrets, bool):
                raise ArenyxaError("PROJECT_MANIFEST_INVALID", "contains_secrets 字段类型无效。", domain="PROJECT")
            if manifest.format not in {PROJECT_FORMAT, *LEGACY_PROJECT_FORMATS}:
                raise ArenyxaError(
                    "PROJECT_FORMAT_UNSUPPORTED", f"不支持的项目格式：{manifest.format}", domain="PROJECT"
                )
            if manifest.contains_secrets:
                raise ArenyxaError(
                    "PROJECT_CONTAINS_SECRETS", "项目包声明包含秘密，必须人工审阅。", domain="PROJECT"
                )
            declared = set(manifest.files)
            actual = {name for name in names if name != "manifest.json" and not name.endswith("/")}
            undeclared = actual - declared
            missing = declared - actual
            if undeclared:
                preview = ", ".join(sorted(undeclared)[:8])
                raise ArenyxaError(
                    "PROJECT_UNDECLARED_FILE", f"项目包包含未写入完整性清单的文件：{preview}", domain="PROJECT"
                )
            if missing:
                preview = ", ".join(sorted(missing)[:8])
                raise ArenyxaError(
                    "PROJECT_CHECKSUM_MISMATCH", f"项目包缺少已声明文件：{preview}", domain="PROJECT"
                )
            for relative, expected in manifest.files.items():
                if (
                    not isinstance(expected, str)
                    or len(expected) != 64
                    or any(ch not in "0123456789abcdefABCDEF" for ch in expected)
                ):
                    raise ArenyxaError(
                        "PROJECT_MANIFEST_INVALID", f"项目文件哈希格式无效：{relative}", domain="PROJECT"
                    )
                if self._hash_zip_entry(archive, relative) != expected.casefold():
                    raise ArenyxaError(
                        "PROJECT_CHECKSUM_MISMATCH", f"项目文件校验失败：{relative}", domain="PROJECT"
                    )
            return manifest

    def unpack(self, package: Path, destination: Path) -> ProjectManifest:
        






        manifest = self.validate(package)
        destination = destination.expanduser()
        parent = destination.parent.resolve()
        parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.is_symlink() or not destination.is_dir():
                raise ArenyxaError(
                    "PROJECT_DESTINATION_INVALID", "项目解压目标必须是普通目录。", domain="PROJECT"
                )
            if any(destination.iterdir()):
                raise ArenyxaError(
                    "PROJECT_DESTINATION_NOT_EMPTY", "项目解压目标目录必须为空。", domain="PROJECT"
                )

        stage = Path(tempfile.mkdtemp(prefix=f".{destination.name or 'project'}.unpack-", dir=parent))
        try:
            self._extract_validated(package, stage)
                                                                                             
                                                                 
            if destination.exists():
                if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
                    raise ArenyxaError(
                        "PROJECT_DESTINATION_CHANGED",
                        "项目解压期间目标目录发生变化，已取消写入。",
                        domain="PROJECT",
                    )
                destination.rmdir()
            stage.replace(destination)
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        return manifest

    def _extract_validated(self, package: Path, destination_root: Path) -> None:
        destination_root = destination_root.resolve()
        with zipfile.ZipFile(package) as archive:
            self._validate_names(archive.namelist())
            for info in archive.infolist():
                name = info.filename.replace("\\", "/")
                if name.endswith("/"):
                    continue
                                                                                          
                                                                                        
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if (unix_mode & 0o170000) == 0o120000:
                    raise ArenyxaError("PROJECT_SYMLINK_ENTRY", f"项目包包含符号链接：{name}", domain="PROJECT")
                target = (destination_root / name).resolve()
                if target != destination_root and destination_root not in target.parents:
                    raise ArenyxaError("PROJECT_PATH_TRAVERSAL", f"非法项目路径：{name}", domain="PROJECT")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("xb") as output:
                    written = 0
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        written += len(block)
                        if written > info.file_size:
                            raise ArenyxaError(
                                "PROJECT_ARCHIVE_LIMIT", f"项目文件解压大小异常：{name}", domain="PROJECT"
                            )
                        output.write(block)
                    if written != info.file_size:
                        raise ArenyxaError(
                            "PROJECT_ARCHIVE_TRUNCATED", f"项目文件解压不完整：{name}", domain="PROJECT"
                        )

    @staticmethod
    def _validate_names(names: list[str]) -> None:
        portable_seen: set[str] = set()
        reserved_windows = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
        for name in names:
            normalized = name.replace("\\", "/")
            path = Path(normalized)
            if path.is_absolute() or ".." in path.parts or ":" in name:
                raise ArenyxaError("PROJECT_PATH_TRAVERSAL", f"非法项目路径：{name}", domain="PROJECT")
            cleaned_parts: list[str] = []
            for part in path.parts:
                if part in {"", "."}:
                    continue
                portable = part.rstrip(" .")
                if not portable:
                    raise ArenyxaError("PROJECT_PATH_COLLISION", f"项目路径在 Windows 上无效：{name}", domain="PROJECT")
                if portable.split(".", 1)[0].upper() in reserved_windows:
                    raise ArenyxaError("PROJECT_PATH_COLLISION", f"项目路径使用 Windows 保留名称：{name}", domain="PROJECT")
                cleaned_parts.append(portable.casefold())
            portable_key = "/".join(cleaned_parts)
            if portable_key in portable_seen:
                raise ArenyxaError(
                    "PROJECT_PATH_COLLISION",
                    f"项目包包含跨平台会冲突的路径：{name}",
                    domain="PROJECT",
                )
            portable_seen.add(portable_key)


    @staticmethod
    def _hash_zip_entry(archive: zipfile.ZipFile, relative: str) -> str:
        digest = hashlib.sha256()
        with archive.open(relative, "r") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


                                                                                      
ArenyxaProjectService = ArenyxaProjectService
