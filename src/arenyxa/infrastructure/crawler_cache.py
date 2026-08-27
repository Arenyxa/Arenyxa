"""Bounded development cache/replay for crawler HTTP responses.

The cache never persists request headers, cookies, proxy credentials, or bodies of
non-idempotent requests. Cache keys are one-way SHA-256 digests of the effective
request identity. This module is intended for deterministic development/replay,
not as an authentication/session store.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from arenyxa.domain.models import FetchResponse, RequestSpec
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_text


@dataclass(slots=True)
class CachePolicy:
    root: str = ""
    mode: str = "off"  # off | read | write | read-write
    ttl_seconds: float = 3600.0
    max_entries: int = 2000
    max_body_bytes: int = 16 * 1024 * 1024

    def normalized(self) -> "CachePolicy":
        mode = str(self.mode or "off").strip().casefold()
        if mode not in {"off", "read", "write", "read-write"}:
            raise ValueError(f"Unsupported crawler cache mode: {self.mode}")
        return CachePolicy(
            root=str(self.root or "").strip(),
            mode=mode,
            ttl_seconds=max(1.0, min(float(self.ttl_seconds), 30 * 86400.0)),
            max_entries=max(1, min(int(self.max_entries), 100_000)),
            max_body_bytes=max(1024, min(int(self.max_body_bytes), 128 * 1024 * 1024)),
        )


class CrawlerResponseCache:
    """Atomic, bounded response cache for GET/HEAD development workflows."""

    def __init__(self, policy: CachePolicy) -> None:
        self.policy = policy.normalized()
        self._lock = threading.RLock()
        self._root = Path(self.policy.root).expanduser().resolve() if self.policy.root else None
        if self._root is not None and self.policy.mode != "off":
            self._root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _key(spec: RequestSpec) -> str:
        # Never persist request secrets. Hashing still makes authenticated requests
        # distinct without retaining headers/cookies themselves.
        payload = json.dumps({
            "method": spec.method.upper(),
            "url": spec.url,
            "query": sorted(dict(spec.query).items()),
            "headers_sha256": hashlib.sha256(json.dumps(sorted(dict(spec.headers).items())).encode()).hexdigest(),
            "cookies_sha256": hashlib.sha256(json.dumps(sorted(dict(spec.cookies).items())).encode()).hexdigest(),
            "body_sha256": hashlib.sha256((spec.body or "").encode()).hexdigest(),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _paths(self, key: str) -> tuple[Path, Path]:
        assert self._root is not None
        return self._root / f"{key}.json", self._root / f"{key}.body"

    def readable(self) -> bool:
        return self._root is not None and self.policy.mode in {"read", "read-write"}

    def writable(self) -> bool:
        return self._root is not None and self.policy.mode in {"write", "read-write"}

    def get(self, spec: RequestSpec) -> FetchResponse | None:
        if not self.readable() or spec.method.upper() not in {"GET", "HEAD"}:
            return None
        meta_path, body_path = self._paths(self._key(spec))
        with self._lock:
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                created = float(meta["created_at"])
                if time.time() - created > self.policy.ttl_seconds:
                    return None
                body = body_path.read_bytes()
            except (FileNotFoundError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
                return None
        if len(body) > self.policy.max_body_bytes:
            return None
        return FetchResponse(
            url=spec.url,
            final_url=str(meta.get("final_url") or spec.url),
            status=int(meta.get("status") or 0),
            headers={str(k): str(v) for k, v in dict(meta.get("headers") or {}).items()},
            body=body,
            elapsed_ms=0.0,
            encoding=str(meta.get("encoding") or "utf-8"),
            content_type=str(meta.get("content_type") or ""),
            redirect_chain=[str(v) for v in list(meta.get("redirect_chain") or [])[:64]],
            error=None,
        )

    def put(self, spec: RequestSpec, response: FetchResponse) -> bool:
        if not self.writable() or spec.method.upper() not in {"GET", "HEAD"}:
            return False
        if len(response.body) > self.policy.max_body_bytes:
            return False
        key = self._key(spec)
        meta_path, body_path = self._paths(key)
        metadata: dict[str, Any] = {
            "schema": "arenyxa.crawler-cache/v1",
            "created_at": time.time(),
            "final_url": response.final_url,
            "status": int(response.status),
            "headers": _safe_response_headers(response.headers),
            "encoding": response.encoding,
            "content_type": response.content_type,
            "redirect_chain": list(response.redirect_chain)[:64],
        }
        with self._lock:
            atomic_write_bytes(body_path, bytes(response.body))
            atomic_write_text(meta_path, json.dumps(metadata, ensure_ascii=False, sort_keys=True), encoding="utf-8")
            self._prune_locked()
        return True

    def _prune_locked(self) -> None:
        assert self._root is not None
        metas = sorted(self._root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for meta in metas[self.policy.max_entries:]:
            body = meta.with_suffix(".body")
            try:
                meta.unlink(missing_ok=True)
                body.unlink(missing_ok=True)
            except OSError:
                continue

    def clear(self) -> int:
        if self._root is None:
            return 0
        count = 0
        with self._lock:
            for item in self._root.iterdir():
                if item.suffix in {".json", ".body"}:
                    try:
                        item.unlink()
                        count += 1
                    except OSError:
                        continue
        return count


def _safe_response_headers(headers: dict[str, str]) -> dict[str, str]:
    sensitive = {"set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-access-token"}
    return {str(k): ("<redacted>" if str(k).casefold() in sensitive else str(v)[:8192]) for k, v in list(headers.items())[:256]}
