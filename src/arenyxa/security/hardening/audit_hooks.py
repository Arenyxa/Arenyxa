from __future__ import annotations


def security_block_event(reason: str) -> dict:
    return {"event": "security_block", "reason": reason}
