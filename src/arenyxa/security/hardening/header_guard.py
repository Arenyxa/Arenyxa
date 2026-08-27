from __future__ import annotations


MAX_HEADER_SIZE = 64 * 1024


def validate_header_size(headers: bytes) -> bool:
    if len(headers) > MAX_HEADER_SIZE:
        raise ValueError("HTTP headers exceed configured limit")
    return True
