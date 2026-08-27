from __future__ import annotations

MAX_HEADER_COUNT = 256
MAX_SINGLE_HEADER_SIZE = 8192


def validate_headers(headers: dict[str, str]) -> bool:
    if len(headers) > MAX_HEADER_COUNT:
        raise ValueError("too many headers")
    for key, value in headers.items():
        if len(key) + len(value) > MAX_SINGLE_HEADER_SIZE:
            raise ValueError("header too large")
        if "\\r" in value or "\\n" in value:
            raise ValueError("invalid header characters")
    return True
