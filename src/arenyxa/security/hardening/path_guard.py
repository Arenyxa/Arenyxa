from __future__ import annotations

from pathlib import Path


class UnsafePathError(Exception):
    """Marker type for UnsafePathError."""


def ensure_safe_path(path: str, base: str) -> Path:
    target = Path(path).resolve()
    root = Path(base).resolve()
    if root not in target.parents and target != root:
        raise UnsafePathError(f"Path escapes base directory: {target}")
    return target
