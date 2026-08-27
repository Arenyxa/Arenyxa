from __future__ import annotations

import hashlib


def file_integrity(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
