from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_MAX_ARGC = 4096
_MAX_ARG_CHARS = 131_072


def validated_argv(argv: Sequence[Any]) -> list[str]:
    """Normalize an argv vector and reject forms that can blur process boundaries.

    This validator is intentionally compatible with developer-mode PowerShell/CMD commands:
    shell metacharacters are legal *arguments* when an explicit shell executable is the first
    argv item.  The invariant enforced here is that Python never delegates parsing to
    ``shell=True`` and every argument is a bounded, NUL-free scalar.
    """
    if isinstance(argv, (str, bytes, bytearray)):
        raise TypeError("subprocess argv must be a sequence, not a shell command string")
    if not isinstance(argv, Sequence):
        raise TypeError("subprocess argv must be a sequence")
    if not argv or len(argv) > _MAX_ARGC:
        raise ValueError("subprocess argv has an invalid argument count")

    normalized: list[str] = []
    total = 0
    for raw in argv:
        if isinstance(raw, bytes):
            value = os.fsdecode(raw)
        elif isinstance(raw, (str, Path)) or hasattr(raw, "__fspath__"):
            value = os.fspath(raw)
        elif isinstance(raw, (int, float)) and not isinstance(raw, bool):
            value = str(raw)
        else:
            raise TypeError(f"unsupported subprocess argument type: {type(raw).__name__}")
        if "\x00" in value:
            raise ValueError("subprocess arguments may not contain NUL")
        total += len(value)
        if total > _MAX_ARG_CHARS:
            raise ValueError("subprocess argv exceeds the bounded command size")
        normalized.append(value)
    return normalized


def subprocess_kwargs(*, shell: bool = False, **kwargs: Any) -> dict[str, Any]:
    """Centralize the no-shell invariant for call sites that build kwargs dynamically."""
    if shell:
        raise ValueError("shell=True is forbidden; invoke the intended shell executable explicitly")
    result = dict(kwargs)
    result["shell"] = False
    return result
