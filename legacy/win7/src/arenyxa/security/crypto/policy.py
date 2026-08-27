from __future__ import annotations

import hashlib


ALLOWED_HASHES = {"sha256", "sha512"}


def secure_digest(data: bytes, algorithm: str = "sha256") -> str:
    """Generate approved integrity digest."""
    name = algorithm.lower()
    if name not in ALLOWED_HASHES:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return hashlib.new(name, data).hexdigest()
