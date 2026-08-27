from __future__ import annotations


def recovery_checkpoint(name: str) -> dict:
    return {
        "checkpoint": name,
        "ready": True,
    }
