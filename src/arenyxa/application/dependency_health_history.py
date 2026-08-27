from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence

from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited

_STATE_SCORE = {"healthy": 0, "warning": 1, "critical": 2}
_MAX_SNAPSHOTS = 96
_MAX_FILE_BYTES = 2 * 1024 * 1024


class DependencyHealthHistoryStore:
    """Bounded local history for predictive dependency-health signals."""

    def __init__(self, root: Path) -> None:
        self.path = Path(root) / "health" / "dependency_history.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            raw = read_text_limited(self.path, _MAX_FILE_BYTES)
            value = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            return []
        if not isinstance(value, list):
            return []
        return [dict(item) for item in value[-_MAX_SNAPSHOTS:] if isinstance(item, Mapping)]

    def record(self, snapshot: Mapping[str, Any]) -> None:
        compact = {
            "generated_at": str(snapshot.get("generated_at", "")),
            "overall": str(snapshot.get("overall", "unknown")),
            "probes": [
                {
                    "component": str(item.get("component", "")),
                    "state": str(item.get("state", "unknown")),
                    "latency_ms": item.get("latency_ms"),
                    "metrics": dict(item.get("metrics") or {}),
                }
                for item in list(snapshot.get("probes") or [])
                if isinstance(item, Mapping) and str(item.get("component", ""))
            ],
        }
        with self._lock:
            rows = self._load()
            rows.append(compact)
            atomic_write_json(self.path, rows[-_MAX_SNAPSHOTS:], mode=0o600)

    def trend(self, component: str, *, window: int = 8) -> dict[str, Any]:
        name = str(component)
        samples: list[dict[str, Any]] = []
        for snapshot in self._load():
            for item in list(snapshot.get("probes") or []):
                if isinstance(item, Mapping) and str(item.get("component", "")) == name:
                    samples.append(dict(item))
                    break
        samples = samples[-max(3, min(24, int(window))):]
        if len(samples) < 3:
            return {"direction": "insufficient-data", "samples": len(samples), "forecast": "unknown"}
        scores = [float(_STATE_SCORE.get(str(item.get("state", "")).casefold(), 1)) for item in samples]
        latencies = [item.get("latency_ms") for item in samples]
        numeric = [float(item) for item in latencies if isinstance(item, (int, float))]
        state_delta = scores[-1] - scores[0]
        latency_delta = (numeric[-1] - numeric[0]) if len(numeric) >= 2 else 0.0
        if state_delta > 0 or latency_delta > max(25.0, abs(numeric[0]) * 0.25 if numeric else 25.0):
            direction = "degrading"
        elif state_delta < 0 or latency_delta < -max(25.0, abs(numeric[0]) * 0.25 if numeric else 25.0):
            direction = "improving"
        else:
            direction = "stable"
        latest = str(samples[-1].get("state", "unknown")).casefold()
        forecast = "warning" if latest == "healthy" and direction == "degrading" else (
            "critical" if latest == "warning" and direction == "degrading" else latest
        )
        return {
            "direction": direction,
            "samples": len(samples),
            "forecast": forecast,
            "state_delta": round(state_delta, 3),
            "latency_delta_ms": round(latency_delta, 3),
        }

    def trends_for(self, components: Sequence[str]) -> dict[str, dict[str, Any]]:
        return {str(component): self.trend(str(component)) for component in components}
