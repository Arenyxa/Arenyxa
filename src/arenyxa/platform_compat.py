from __future__ import annotations

import os
import sys
from dataclasses import field
from typing import Any, Optional

from arenyxa.branding import LEGACY_RUNTIME_TIER_ENV, RUNTIME_TIER_ENV
from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError


@dataclass(frozen=True, slots=True)
class WindowsVersion:
    major: int
    minor: int
    build: int = 0
    service_pack_major: int = 0

    @property
    def is_windows_7(self) -> bool:
        return (self.major, self.minor) == (6, 1)

    @property
    def is_pre_windows_10(self) -> bool:
        return (self.major, self.minor) < (10, 0)


@dataclass(frozen=True, slots=True)
class RuntimeCompatibility:
    tier: str
    python_min: tuple[int, int]
    python_max_exclusive: tuple[int, int]
    qt_binding: str
    legacy: bool
    reduced_visuals: bool
    browser_automation: bool
    modern_backdrop: bool
    feature_policy: str = "active-development"
    feature_parity_required: bool = True
    notes: tuple[str, ...] = field(default_factory=tuple)


MODERN_RUNTIME = RuntimeCompatibility(
    tier="modern",
    python_min=(3, 11),
    python_max_exclusive=(3, 14),
    qt_binding="PySide6",
    legacy=False,
    reduced_visuals=False,
    browser_automation=True,
    modern_backdrop=True,
)

LEGACY_RUNTIME = RuntimeCompatibility(
    tier="legacy-enterprise",
    python_min=(3, 8),
    python_max_exclusive=(3, 9),
    qt_binding="PySide2",
    legacy=True,
    reduced_visuals=True,
    browser_automation=False,
    modern_backdrop=False,
    feature_policy="security-maintenance",
    feature_parity_required=False,
    notes=(
        "Windows 7 requires SP1, KB2533623 and the platform updates required by Python 3.8/UCRT.",
        "Legacy UI uses Qt 5/PySide2 and disables unsupported modern visual effects.",
        "Legacy Enterprise is feature-frozen: only critical compatibility and security fixes are backported.",
        "New Modern-lane features do not require PySide2/Python 3.8 feature parity.",
        "Legacy Enterprise is a compatibility lane; security-sensitive or internet-exposed deployments should prefer the modern runtime.",
    ),
)


def windows_version() -> Optional[WindowsVersion]:
    if os.name != "nt":
        return None
    raw = sys.getwindowsversion()
    return WindowsVersion(
        int(raw.major),
        int(raw.minor),
        int(raw.build),
        int(getattr(raw, "service_pack_major", 0) or 0),
    )


def select_runtime(
    *,
    py_version: tuple[int, int] | None = None,
    win_version: WindowsVersion | None = None,
    platform_name: str | None = None,
    runtime_tier: str | None = None,
) -> RuntimeCompatibility:
    
    py_version = py_version or tuple(sys.version_info[:2])
    platform_name = platform_name or os.name
    if platform_name != "nt":
        return MODERN_RUNTIME

    win_version = win_version or windows_version()
    if win_version is None:
        return MODERN_RUNTIME
    if (win_version.major, win_version.minor) < (6, 1):
        raise ArenyxaError(
            "WINDOWS_RUNTIME_UNSUPPORTED",
            "Arenyxa 最低支持 Windows 7 SP1 x64。",
            domain="DEPENDENCY",
        )
    if win_version.is_windows_7 and win_version.service_pack_major < 1:
        raise ArenyxaError(
            "WINDOWS_7_SP1_REQUIRED",
            "Windows 7 必须安装 Service Pack 1 才能运行 Arenyxa Legacy Enterprise。",
            domain="DEPENDENCY",
        )

                                                                                       
                                                                                          
                                                                                          
                                                                          
    explicit_tier = runtime_tier
    if explicit_tier is None:
        explicit_tier = os.environ.get(RUNTIME_TIER_ENV) or os.environ.get(
            LEGACY_RUNTIME_TIER_ENV
        )
    if str(explicit_tier or "").strip().casefold() == LEGACY_RUNTIME.tier:
        return LEGACY_RUNTIME

                                                                                         
                                                                                    
    if win_version.is_pre_windows_10 or (win_version.major, win_version.minor) == (10, 0) and win_version.build < 17763:
        return LEGACY_RUNTIME
    return MODERN_RUNTIME


def windows_reduced_motion_requested(
    *,
    platform_name: str | None = None,
    system_parameters_info: Any = None,
) -> bool:
    






    if (platform_name or os.name) != "nt":
        return False
    try:
        import ctypes

        enabled = ctypes.c_int(1)
        query = system_parameters_info or ctypes.windll.user32.SystemParametersInfoW
        success = query(0x1042, 0, ctypes.byref(enabled), 0)                              
        return bool(success) and not bool(enabled.value)
    except (AttributeError, OSError, TypeError, ValueError):
                                                                                        
                                                                                         
                                                                    
        return False


def validate_python_for_runtime(
    runtime: RuntimeCompatibility,
    py_version: tuple[int, int, int] | None = None,
    *,
    is_64bit: bool | None = None,
) -> None:
    version = py_version or tuple(sys.version_info[:3])
    if is_64bit is None:
        is_64bit = sys.maxsize > 2**32
    if not is_64bit:
        raise ArenyxaError(
            "WINDOWS_X64_REQUIRED",
            "Arenyxa 仅支持 64-bit (x64) Windows 运行时。",
            domain="DEPENDENCY",
        )
    major_minor = tuple(version[:2])
    if not (runtime.python_min <= major_minor < runtime.python_max_exclusive):
        if runtime.legacy:
            requirement = "Python 3.8.x"
        else:
            requirement = "Python 3.11–3.13"
        raise ArenyxaError(
            "PYTHON_RUNTIME_UNSUPPORTED",
            f"当前 Python {version[0]}.{version[1]}.{version[2]} 不符合 {runtime.tier} 运行时要求；需要 {requirement}。",
            domain="DEPENDENCY",
            context={"python_version": ".".join(str(part) for part in version), "runtime_tier": runtime.tier},
        )


def apply_legacy_environment(runtime: RuntimeCompatibility) -> None:
    
    if not runtime.legacy:
        return
    os.environ.setdefault(RUNTIME_TIER_ENV, runtime.tier)
                                                                                      
    os.environ.setdefault(LEGACY_RUNTIME_TIER_ENV, runtime.tier)
    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")
                                                                                       
                                                                                       
    os.environ.setdefault("QT_OPENGL", "software")
