from __future__ import annotations

import idna
import unicodedata


def normalize_idn(host: str) -> str:
    normalized = unicodedata.normalize("NFKC", host)
    return idna.encode(normalized).decode("ascii")
