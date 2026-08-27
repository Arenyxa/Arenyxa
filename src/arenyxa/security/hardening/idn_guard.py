from __future__ import annotations

import unicodedata


def normalize_hostname(hostname: str) -> str:
    return unicodedata.normalize("NFKC", hostname).lower()


def has_suspicious_unicode(hostname: str) -> bool:
    normalized = normalize_hostname(hostname)
    return normalized != hostname.lower()
