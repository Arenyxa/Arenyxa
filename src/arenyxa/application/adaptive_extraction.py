"""Persistent adaptive-selector history and version graph for Phase 3."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

from arenyxa.application.nextgen_browser import SelectorFingerprint, SelectorStudio
from arenyxa.infrastructure.atomic_io import atomic_write_json


@dataclass(slots=True)
class SelectorVersion:
    version_id: str
    selector: str
    selector_type: str
    fingerprint: dict[str, Any]
    parent_version_id: str = ""
    confidence: float = 1.0
    success_count: int = 0
    failure_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_seen_at: float = field(default_factory=time.time)


class AdaptiveSelectorStore:
    SCHEMA_VERSION = 1

    def __init__(self, path: str | Path, *, max_versions_per_key: int = 128) -> None:
        self.path = Path(path)
        self.max_versions_per_key = max(4, min(int(max_versions_per_key), 2048))
        self._lock = threading.RLock()
        self._data: dict[str, list[dict[str, Any]]] = {}
        self._load()

    @staticmethod
    def key(site: str, logical_name: str) -> str:
        return hashlib.sha256(f"{site.casefold().strip()}\0{logical_name.casefold().strip()}".encode()).hexdigest()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if int(payload.get("schema_version", 0)) != self.SCHEMA_VERSION:
                return
            rows = payload.get("selectors", {})
            if isinstance(rows, dict):
                self._data = {str(k): list(v) for k, v in rows.items() if isinstance(v, list)}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self._data = {}

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.path, {"schema_version": self.SCHEMA_VERSION, "selectors": self._data})

    def remember(self, site: str, logical_name: str, selector: str, selector_type: str, fingerprint: SelectorFingerprint | Mapping[str, Any], *, parent_version_id: str = "", confidence: float = 1.0) -> SelectorVersion:
        fp = asdict(fingerprint) if isinstance(fingerprint, SelectorFingerprint) else dict(fingerprint)
        identity = hashlib.sha256(json.dumps([selector_type, selector, fp], sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]
        item = SelectorVersion(identity, selector, selector_type, fp, parent_version_id, max(0.0, min(1.0, float(confidence))))
        bucket_key = self.key(site, logical_name)
        with self._lock:
            bucket = self._data.setdefault(bucket_key, [])
            for existing in bucket:
                if existing.get("version_id") == identity:
                    existing["last_seen_at"] = time.time()
                    self._persist()
                    return SelectorVersion(**existing)
            bucket.append(asdict(item))
            if len(bucket) > self.max_versions_per_key:
                del bucket[:-self.max_versions_per_key]
            self._persist()
        return item

    def versions(self, site: str, logical_name: str) -> list[SelectorVersion]:
        with self._lock:
            return [SelectorVersion(**dict(item)) for item in self._data.get(self.key(site, logical_name), ())]

    def record_result(self, site: str, logical_name: str, version_id: str, *, success: bool) -> None:
        with self._lock:
            for item in self._data.get(self.key(site, logical_name), ()):
                if item.get("version_id") == version_id:
                    field_name = "success_count" if success else "failure_count"
                    item[field_name] = int(item.get(field_name, 0)) + 1
                    item["last_seen_at"] = time.time()
                    self._persist()
                    return
            raise KeyError(version_id)


class AdaptiveExtractionEngine:
    """Remember selectors and conservatively heal them after DOM changes."""

    def __init__(self, store: AdaptiveSelectorStore, *, studio: SelectorStudio | None = None) -> None:
        self.store = store
        self.studio = studio or SelectorStudio()

    def remember(self, site: str, logical_name: str, markup: str, selector: str, selector_type: str = "css") -> SelectorVersion:
        analysis = self.studio.analyze(markup, selector, selector_type)
        fingerprint = analysis.get("fingerprint")
        if not fingerprint:
            raise ValueError("selector did not match an element and cannot be remembered")
        return self.store.remember(site, logical_name, selector, selector_type, fingerprint)

    def resolve(self, site: str, logical_name: str, markup: str, *, min_confidence: float = 0.92, auto_apply: bool = False) -> dict[str, Any]:
        versions = self.store.versions(site, logical_name)
        if not versions:
            return {"status": "unknown", "selected": None, "candidates": [], "reason": "no selector history"}
        latest = versions[-1]
        direct = self.studio.analyze(markup, latest.selector, latest.selector_type)
        if direct["matches"] == 1:
            self.store.record_result(site, logical_name, latest.version_id, success=True)
            return {"status": "stable", "selected": {"selector": latest.selector, "selector_type": latest.selector_type, "confidence": 1.0, "version_id": latest.version_id}, "candidates": []}
        history = []
        for item in versions:
            total = item.success_count + item.failure_count
            history.append({"selector": item.selector, "success": item.success_count >= item.failure_count if total else True})
        decision = self.studio.heal_with_policy(markup, latest.fingerprint, history=history, auto_apply=auto_apply, min_confidence=min_confidence)
        selected = decision.get("selected")
        if selected:
            healed = self.store.remember(site, logical_name, selected["selector"], selected["selector_type"], self.studio.analyze(markup, selected["selector"], selected["selector_type"])["fingerprint"], parent_version_id=latest.version_id, confidence=float(selected["confidence"]))
            selected = dict(selected)
            selected["version_id"] = healed.version_id
            return {"status": "healed", "selected": selected, "candidates": decision["candidates"]}
        self.store.record_result(site, logical_name, latest.version_id, success=False)
        return {"status": "review-required", "selected": None, "candidates": decision["candidates"], "reason": decision["decision"]}
