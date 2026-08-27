from __future__ import annotations

import hashlib
import json
from typing import Any

from arenyxa.compat import dataclass


@dataclass(frozen=True, slots=True)
class WorkflowResumeValidation:
    """Result of checkpoint preflight and isolated deterministic replay."""

    execution_id: str
    valid: bool
    replayed: bool
    definition_hash: str
    next_input_identity: str = ""
    output_count: int = 0
    error_count: int = 0
    warnings: tuple[str, ...] = ()
    checkpoint_generation: int = 0
    integrity_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "valid": self.valid,
            "replayed": self.replayed,
            "definition_hash": self.definition_hash,
            "next_input_identity": self.next_input_identity,
            "output_count": self.output_count,
            "error_count": self.error_count,
            "warnings": list(self.warnings),
            "checkpoint_generation": self.checkpoint_generation,
            "integrity_verified": self.integrity_verified,
        }


def checkpoint_digest(checkpoint: dict[str, Any] | Any) -> str:
    payload = {key: value for key, value in dict(checkpoint).items() if key != "checkpoint_sha256"}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
