from __future__ import annotations

import json
import math
import os
from dataclasses import asdict
from arenyxa.compat import dataclass
from pathlib import Path
from typing import Any

from arenyxa.branding import (
    APP_NAME,
    DATA_DIR_ENV,
    DATABASE_FILENAME,
    LEGACY_APP_NAME,
    LEGACY_DATA_DIR_ENV,
    LEGACY_DATABASE_FILENAME,
    LOG_FILENAME,
    LEGACY_LOG_FILENAME,
)
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited
SCHEMA_VERSION = 9


@dataclass(slots=True)
class AppPaths:
    root: Path
    database: Path
    logs: Path
    cache: Path
    exports: Path
    captures: Path
    projects: Path
    plugins: Path
    profiles: Path

    @classmethod
    def discover(cls, override: Path | None = None) -> AppPaths:
        if override is None:
            configured = os.getenv(DATA_DIR_ENV) or os.getenv(LEGACY_DATA_DIR_ENV)
            if configured:
                override = Path(configured)
            else:
                base = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
                canonical = base / APP_NAME
                legacy = base / LEGACY_APP_NAME
                                                                                                                 
                                                                                      
                                                           
                override = legacy if legacy.exists() and not canonical.exists() else canonical
        root = override.expanduser().resolve()
        canonical_database = root / DATABASE_FILENAME
        legacy_database = root / LEGACY_DATABASE_FILENAME
        database = (
            legacy_database
            if legacy_database.exists() and not canonical_database.exists()
            else canonical_database
        )
        return cls(
            root=root,
            database=database,
            logs=root / "logs",
            cache=root / "cache",
            exports=root / "exports",
            captures=root / "captures",
            projects=root / "projects",
            plugins=root / "plugins",
            profiles=root / "profiles",
        )

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for path in (
            self.logs,
            self.cache,
            self.exports,
            self.captures,
            self.projects,
            self.plugins,
            self.profiles,
        ):
            path.mkdir(parents=True, exist_ok=True)

    @property
    def log_file(self) -> Path:
        
        return self.logs / LOG_FILENAME

    @property
    def readable_log_file(self) -> Path:
        
        canonical = self.logs / LOG_FILENAME
        legacy = self.logs / LEGACY_LOG_FILENAME
        if canonical.exists() or not legacy.exists():
            return canonical
        return legacy


@dataclass(slots=True)
class AppSettings:
    schema_version: int = SCHEMA_VERSION
    locale: str = "system"
    theme: str = "modern_dark"
    reduce_motion: bool = False
    high_contrast: bool = False
    glass_strength: float = 0.82
    motion_strength: float = 0.88
    blur_strength: float = 22.0
    edge_flow: bool = False
    live_data_motion: bool = True
    animation_mode: str = "auto"
    performance_mode: str = "auto"
    ui_scale_mode: str = "auto"
    ui_scale_percent: int = 100
    left_sidebar_collapsed: bool = False
    advanced_nav_expanded: bool = False
    developer_nav_expanded: bool = False
    inspector_collapsed: bool = False
    max_workers: int = 4
    request_concurrency: int = 8
    per_host_concurrency: int = 4
    adaptive_request_concurrency: bool = True
    resource_governor_enabled: bool = True
    resource_cpu_soft_percent: int = 88
    resource_memory_soft_percent: int = 82
    resource_min_free_disk_mb: int = 512
    resource_max_browser_instances: int = 4
    max_response_bytes: int = 32 * 1024 * 1024
    default_timeout_seconds: float = 30.0
    diagnostics_include_paths: bool = False
    developer_mode: bool = False
    developer_terms_version: int = 0
    developer_terms_accepted_at: str = ""
                                                                                           
    experience_profile: str = ""
    experience_setup_completed: bool = False

    @classmethod
    def load(cls, path: Path) -> AppSettings:
        if not path.exists():
            return cls()
        try:
            raw_value: Any = json.loads(read_text_limited(path, 2 * 1024 * 1024, encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                                                                                         
                                                                                         
                                                                        
            return cls()
        if not isinstance(raw_value, dict):
            return cls()
        raw: dict[str, Any] = raw_value
        defaults = cls()
        values = asdict(defaults)
        allowed = cls.__dataclass_fields__.keys()
        for key, value in raw.items():
            if key in allowed:
                values[key] = value

        def clamp_float(name: str, low: float, high: float, fallback: float) -> None:
            candidate = values.get(name, fallback)
            if isinstance(candidate, bool):
                value = fallback
            else:
                try:
                    value = float(candidate)
                except (TypeError, ValueError, OverflowError):
                    value = fallback
            if not math.isfinite(value):
                value = fallback
            values[name] = max(low, min(high, value))

        def clamp_int(name: str, low: int, high: int, fallback: int) -> None:
            candidate = values.get(name, fallback)
            if isinstance(candidate, bool):
                value = fallback
            else:
                try:
                    value = int(candidate)
                except (TypeError, ValueError, OverflowError):
                    value = fallback
            values[name] = max(low, min(high, value))

        for name in (
            "reduce_motion", "high_contrast", "edge_flow", "live_data_motion",
            "left_sidebar_collapsed", "advanced_nav_expanded", "developer_nav_expanded",
            "inspector_collapsed", "diagnostics_include_paths", "developer_mode",
            "adaptive_request_concurrency", "resource_governor_enabled", "experience_setup_completed",
        ):
            if not isinstance(values.get(name), bool):
                values[name] = getattr(defaults, name)
        clamp_float("glass_strength", 0.0, 1.0, defaults.glass_strength)
        clamp_float("motion_strength", 0.0, 1.0, defaults.motion_strength)
        clamp_float("blur_strength", 0.0, 64.0, defaults.blur_strength)
        clamp_float("default_timeout_seconds", 1.0, 600.0, defaults.default_timeout_seconds)
        clamp_int("developer_terms_version", 0, 1000, defaults.developer_terms_version)
        clamp_int("ui_scale_percent", 85, 160, defaults.ui_scale_percent)
        if values.get("ui_scale_mode") not in {"auto", "manual"}:
            values["ui_scale_mode"] = defaults.ui_scale_mode
        if values.get("experience_profile") not in {"", "personal", "power", "professional", "developer"}:
            values["experience_profile"] = defaults.experience_profile
        if not isinstance(values.get("developer_terms_accepted_at"), str):
            values["developer_terms_accepted_at"] = defaults.developer_terms_accepted_at
        elif len(values["developer_terms_accepted_at"]) > 128:
            values["developer_terms_accepted_at"] = values["developer_terms_accepted_at"][:128]
        clamp_int("max_workers", 1, 64, defaults.max_workers)
        clamp_int("request_concurrency", 1, 64, defaults.request_concurrency)
        clamp_int("per_host_concurrency", 1, 32, defaults.per_host_concurrency)
        values["per_host_concurrency"] = min(values["per_host_concurrency"], values["request_concurrency"])
        clamp_int("resource_cpu_soft_percent", 40, 98, defaults.resource_cpu_soft_percent)
        clamp_int("resource_memory_soft_percent", 40, 95, defaults.resource_memory_soft_percent)
        clamp_int("resource_min_free_disk_mb", 128, 1024 * 1024, defaults.resource_min_free_disk_mb)
        clamp_int("resource_max_browser_instances", 1, 32, defaults.resource_max_browser_instances)
        clamp_int("max_response_bytes", 1024 * 1024, 1024 * 1024 * 1024, defaults.max_response_bytes)
        if values.get("animation_mode") not in {"auto", "always", "minimal"}:
            values["animation_mode"] = defaults.animation_mode
        if values.get("performance_mode") not in {"auto", "quality", "balanced", "efficiency"}:
            values["performance_mode"] = defaults.performance_mode
                                                                                          
                                                                                     
        if not values.get("developer_mode", False):
            values["developer_nav_expanded"] = False
        supported_locales = {"system", "zh_CN", "zh_TW", "en_US", "fr_FR", "ru_RU", "de_DE", "ja_JP", "ko_KR", "ar_SA", "la_VA"}
        supported_themes = {"modern_dark", "aurora_glass", "clean_light", "terminal_green", "professional_graphite", "blue_productivity"}
        if not isinstance(values.get("locale"), str) or values.get("locale") not in supported_locales:
            values["locale"] = defaults.locale
        if not isinstance(values.get("theme"), str) or values.get("theme") not in supported_themes:
            values["theme"] = defaults.theme
        values["schema_version"] = SCHEMA_VERSION
        return cls(**values)

    def save(self, path: Path) -> None:
                                                                                             
                                                                                     
        atomic_write_json(path, asdict(self), ensure_ascii=False, indent=2)
