from __future__ import annotations

import hashlib
import json
import urllib.request
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from pathlib import Path
from typing import Any

from arenyxa import __display_version__ as __version__
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, NetworkEvent, utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_text_limited


@dataclass(slots=True)
class BrowserProfile:
    id: str
    name: str
    user_agent: str = f"Arenyxa/{__version__}"
    locale: str = "zh-CN"
    proxy: str | None = None
    timezone: str = "Asia/Shanghai"
    secret_refs: dict[str, str] = field(default_factory=dict)
    schema_version: int = 6


class BrowserProfileService:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    @staticmethod
    def _validate_id(profile_id: str) -> str:
        if (
            not isinstance(profile_id, str)
            or not 1 <= len(profile_id) <= 128
            or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in profile_id)
            or profile_id in {".", ".."}
        ):
            raise ArenyxaError("BROWSER_PROFILE_ID_INVALID", "浏览器 Profile ID 无效。", domain="PROFILE")
        return profile_id

    def _profile_path(self, profile_id: str) -> Path:
        safe_id = self._validate_id(profile_id)
        path = (self.root / safe_id / "profile.json").resolve()
        if self.root not in path.parents:
            raise ArenyxaError("BROWSER_PROFILE_PATH_INVALID", "浏览器 Profile 路径越界。", domain="PROFILE")
        return path

    @classmethod
    def _validate_profile(cls, profile: BrowserProfile) -> None:
        cls._validate_id(profile.id)
        if any(not isinstance(value, str) or not value.strip() for value in (
            profile.name, profile.user_agent, profile.locale, profile.timezone
        )):
            raise ArenyxaError("BROWSER_PROFILE_INVALID", "浏览器 Profile 必填字符串字段无效。", domain="PROFILE")
        if profile.proxy is not None:
            if not isinstance(profile.proxy, str):
                raise ArenyxaError("BROWSER_PROFILE_INVALID", "浏览器 Profile proxy 类型无效。", domain="PROFILE")
            if profile.proxy:
                from urllib.parse import urlparse
                parsed = urlparse(profile.proxy)
                try:
                    port = parsed.port
                except ValueError as exc:
                    raise ArenyxaError("BROWSER_PROFILE_INVALID", "浏览器 Profile proxy 端口无效。", domain="PROFILE") from exc
                if parsed.scheme not in {"http", "https"} or not parsed.hostname or (port is not None and not 1 <= port <= 65535):
                    raise ArenyxaError("BROWSER_PROFILE_INVALID", "浏览器 Profile proxy 必须是有效 HTTP/HTTPS URL。", domain="PROFILE")
        if not isinstance(profile.secret_refs, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in profile.secret_refs.items()
        ):
            raise ArenyxaError("BROWSER_PROFILE_INVALID", "浏览器 Profile secret_refs 类型无效。", domain="PROFILE")
        if not isinstance(profile.schema_version, int) or isinstance(profile.schema_version, bool):
            raise ArenyxaError("BROWSER_PROFILE_INVALID", "浏览器 Profile schema_version 无效。", domain="PROFILE")

    def save(self, profile: BrowserProfile) -> Path:
        self._validate_profile(profile)
        path = self._profile_path(profile.id)
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, asdict(profile), ensure_ascii=False, indent=2)
        return path

    def load(self, profile_id: str) -> BrowserProfile:
        path = self._profile_path(profile_id)
        try:
            raw = json.loads(read_text_limited(path, 1024 * 1024, encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("profile root must be object")
            allowed = set(BrowserProfile.__dataclass_fields__)
            if set(raw) - allowed:
                raise ValueError("unknown profile fields")
            profile = BrowserProfile(**raw)
            if any(not isinstance(value, str) for value in (
                profile.id, profile.name, profile.user_agent, profile.locale, profile.timezone
            )):
                raise ValueError("profile string field has invalid type")
            if profile.proxy is not None and not isinstance(profile.proxy, str):
                raise ValueError("profile proxy has invalid type")
            if not isinstance(profile.secret_refs, dict) or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in profile.secret_refs.items()
            ):
                raise ValueError("profile secret_refs has invalid type")
            if not isinstance(profile.schema_version, int) or isinstance(profile.schema_version, bool):
                raise ValueError("profile schema_version has invalid type")
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ArenyxaError("BROWSER_PROFILE_INVALID", "浏览器 Profile 文件损坏或格式无效。", domain="PROFILE") from exc
        self._validate_profile(profile)
        if profile.id != profile_id:
            raise ArenyxaError("BROWSER_PROFILE_INVALID", "浏览器 Profile ID 与存储路径不一致。", domain="PROFILE")
        return profile

    def export_metadata(self, profile_id: str, destination: Path) -> Path:
        profile = self.load(profile_id)
        profile.secret_refs = {name: f"${{secret.{name}}}" for name in profile.secret_refs}
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(destination, asdict(profile), ensure_ascii=False, indent=2)
        return destination


@dataclass(slots=True)
class RegressionBaseline:
    id: str
    name: str
    dom_hash: str
    selector_hits: dict[str, int]
    api_schema: dict[str, str]
    record_count: int
    performance_p95_ms: float
    created_at: str = field(default_factory=utc_now)


class RegressionLab:
    @staticmethod
    def create_baseline(
        baseline_id: str,
        name: str,
        response: FetchResponse,
        selector_hits: dict[str, int],
        api_schema: dict[str, str],
        record_count: int,
        events: list[NetworkEvent],
    ) -> RegressionBaseline:
        durations = sorted(event.timing.get("total_ms", 0.0) for event in events)
        p95 = durations[round((len(durations) - 1) * 0.95)] if durations else 0.0
        return RegressionBaseline(
            baseline_id,
            name,
            hashlib.sha256(response.body).hexdigest(),
            selector_hits,
            api_schema,
            record_count,
            p95,
        )

    @staticmethod
    def compare(before: RegressionBaseline, after: RegressionBaseline) -> dict[str, Any]:
        selector_changes = {
            key: {"before": before.selector_hits.get(key, 0), "after": after.selector_hits.get(key, 0)}
            for key in sorted(set(before.selector_hits) | set(after.selector_hits))
            if before.selector_hits.get(key, 0) != after.selector_hits.get(key, 0)
        }
        return {
            "dom_changed": before.dom_hash != after.dom_hash,
            "selector_changes": selector_changes,
            "schema_added": sorted(set(after.api_schema) - set(before.api_schema)),
            "schema_removed": sorted(set(before.api_schema) - set(after.api_schema)),
            "record_delta": after.record_count - before.record_count,
            "performance_p95_delta_ms": after.performance_p95_ms - before.performance_p95_ms,
            "passed": not selector_changes
            and not (set(before.api_schema) - set(after.api_schema))
            and after.performance_p95_ms <= before.performance_p95_ms * 1.2 + 50,
        }


@dataclass(slots=True)
class MarketplaceItem:
    id: str
    name: str
    version: str
    description: str
    package_url: str
    sha256: str
    permissions: list[str] = field(default_factory=list)
    plugin_dependencies: list[dict[str, str]] = field(default_factory=list)


class WorkflowMarketplaceService:
    

    def load_catalog(self, source: str | Path) -> list[MarketplaceItem]:
        if isinstance(source, Path) or "://" not in str(source):
            path = Path(source)
            try:
                raw = read_text_limited(path, 4 * 1024 * 1024, encoding="utf-8")
            except ValueError as exc:
                raise ArenyxaError("MARKETPLACE_CATALOG_TOO_LARGE", "市场目录超过大小上限。", domain="MARKETPLACE") from exc
        else:
            url = str(source)
            if not url.startswith("https://"):
                raise ArenyxaError("MARKETPLACE_INSECURE_URL", "远程市场目录必须通过 HTTPS 加载。", domain="MARKETPLACE")
            request = urllib.request.Request(url, headers={"User-Agent": f"Arenyxa/{__version__}"})
            with urllib.request.urlopen(request, timeout=15) as response:
                final_url = response.geturl()
                if not str(final_url).startswith("https://"):
                    raise ArenyxaError("MARKETPLACE_INSECURE_REDIRECT", "市场目录重定向到了非 HTTPS 地址。", domain="MARKETPLACE")
                raw_bytes = response.read(4 * 1024 * 1024 + 1)
            if len(raw_bytes) > 4 * 1024 * 1024:
                raise ArenyxaError("MARKETPLACE_CATALOG_TOO_LARGE", "市场目录超过大小上限。", domain="MARKETPLACE")
            raw = raw_bytes.decode("utf-8")
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArenyxaError("MARKETPLACE_CATALOG_INVALID", "市场目录不是有效 JSON。", domain="MARKETPLACE") from exc
        if not isinstance(data, dict) or not isinstance(data.get("items", []), list):
            raise ArenyxaError("MARKETPLACE_CATALOG_INVALID", "市场目录结构无效。", domain="MARKETPLACE")
        result: list[MarketplaceItem] = []
        allowed = set(MarketplaceItem.__dataclass_fields__)
        for raw_item in data.get("items", []):
            if not isinstance(raw_item, dict) or set(raw_item) - allowed:
                raise ArenyxaError("MARKETPLACE_CATALOG_INVALID", "市场条目结构无效。", domain="MARKETPLACE")
            try:
                item = MarketplaceItem(**raw_item)
            except (TypeError, ValueError) as exc:
                raise ArenyxaError("MARKETPLACE_CATALOG_INVALID", "市场条目字段类型无效。", domain="MARKETPLACE") from exc
            if any(not isinstance(value, str) for value in (
                item.id, item.name, item.version, item.description, item.package_url, item.sha256
            )) or not isinstance(item.permissions, list) or not all(isinstance(value, str) for value in item.permissions) or not isinstance(item.plugin_dependencies, list):
                raise ArenyxaError("MARKETPLACE_CATALOG_INVALID", "市场条目字段类型无效。", domain="MARKETPLACE")
            if any(not isinstance(dep, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in dep.items()) for dep in item.plugin_dependencies):
                raise ArenyxaError("MARKETPLACE_CATALOG_INVALID", "市场插件依赖字段格式无效。", domain="MARKETPLACE")
            if len(item.sha256) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in item.sha256):
                raise ArenyxaError("MARKETPLACE_CATALOG_INVALID", f"市场条目 {item.id!r} 的 SHA-256 无效。", domain="MARKETPLACE")
            result.append(item)
        return result

    def install(self, item: MarketplaceItem, destination: Path) -> Path:
        if not item.package_url.startswith("https://"):
            raise ArenyxaError(
                "MARKETPLACE_INSECURE_URL", "工作流包必须通过 HTTPS 下载。", domain="MARKETPLACE"
            )
        request = urllib.request.Request(item.package_url, headers={"User-Agent": f"Arenyxa/{__version__}"})
        with urllib.request.urlopen(request, timeout=30) as response:
            final_url = response.geturl()
            if not str(final_url).startswith("https://"):
                raise ArenyxaError("MARKETPLACE_INSECURE_REDIRECT", "工作流包重定向到了非 HTTPS 地址。", domain="MARKETPLACE")
            package = response.read(64 * 1024 * 1024 + 1)
        if len(package) > 64 * 1024 * 1024:
            raise ArenyxaError(
                "MARKETPLACE_PACKAGE_TOO_LARGE", "工作流包超过大小上限。", domain="MARKETPLACE"
            )
        digest = hashlib.sha256(package).hexdigest()
        if digest != item.sha256.casefold():
            raise ArenyxaError("MARKETPLACE_CHECKSUM_MISMATCH", "工作流包校验失败。", domain="MARKETPLACE")
        atomic_write_bytes(destination, package)
        return destination
