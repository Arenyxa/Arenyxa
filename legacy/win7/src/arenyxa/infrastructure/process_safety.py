from __future__ import annotations

import os
from pathlib import Path
from typing import Any, List, Sequence

_MAX_ARGC = 4096
_MAX_ARG_CHARS = 131072


def validated_argv(argv: Sequence[Any]) -> List[str]:
    if isinstance(argv, (str, bytes, bytearray)):
        raise TypeError("subprocess argv must be a sequence, not a shell command string")
    if not argv or len(argv) > _MAX_ARGC:
        raise ValueError("subprocess argv has an invalid argument count")
    normalized = []
    total = 0
    for raw in argv:
        if isinstance(raw, bytes):
            value = os.fsdecode(raw)
        elif isinstance(raw, (str, Path)) or hasattr(raw, "__fspath__"):
            value = os.fspath(raw)
        elif isinstance(raw, (int, float)) and not isinstance(raw, bool):
            value = str(raw)
        else:
            raise TypeError("unsupported subprocess argument type: " + type(raw).__name__)
        if "\x00" in value:
            raise ValueError("subprocess arguments may not contain NUL")
        total += len(value)
        if total > _MAX_ARG_CHARS:
            raise ValueError("subprocess argv exceeds the bounded command size")
        normalized.append(value)
    return normalized
