from __future__ import annotations

import re

_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\\s*=\\s*['\"][^'\"]+['\"]"),
)


def scan_text(text: str) -> list[str]:
    return [m.group(0) for p in _SECRET_PATTERNS for m in p.finditer(text)]
