from __future__ import annotations


def find_weak_crypto(text: str) -> list[str]:
    hits = []
    lower = text.lower()
    if "md5(" in lower:
        hits.append("md5")
    if "sha1(" in lower:
        hits.append("sha1")
    return hits
