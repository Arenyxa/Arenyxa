from __future__ import annotations

import collections
import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from arenyxa.infrastructure.atomic_io import atomic_write_json, read_bytes_limited

AUTH_THROTTLE_SCHEMA = "arenyxa.enterprise-auth-throttle/v1"
MAX_AUTH_THROTTLE_BYTES = 128 * 1024
MAX_AUTH_THROTTLE_BUCKETS = 256
MAX_AUTH_THROTTLE_DELAY_SECONDS = 30.0
MAX_CORRELATION_ID_LENGTH = 128
_CORRELATION_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")


class AuthThrottleIntegrityError(RuntimeError):
    pass


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _auth_state_key(data_key: bytes) -> bytes:
    return hmac.new(bytes(data_key), b"arenyxa-enterprise-auth-throttle-state-v1", hashlib.sha256).digest()


def _auth_bucket_id(state_key: bytes, username: str) -> str:
    normalized = str(username).strip().casefold()[:128].encode("utf-8")
    return hmac.new(state_key, b"bucket\x00" + normalized, hashlib.sha256).hexdigest()


def load_auth_throttle(path: Path, data_key: bytes) -> "collections.OrderedDict[str, tuple[int, float]]":
    path = Path(path)
    if not path.exists():
        return collections.OrderedDict()
    if path.is_symlink():
        raise AuthThrottleIntegrityError("Enterprise authentication throttle state cannot be a symbolic link")
    try:
        raw = read_bytes_limited(path, MAX_AUTH_THROTTLE_BYTES)
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise AuthThrottleIntegrityError("Enterprise authentication throttle state cannot be decoded") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "entries", "mac"}:
        raise AuthThrottleIntegrityError("Enterprise authentication throttle state schema is invalid")
    if value.get("schema") != AUTH_THROTTLE_SCHEMA or not isinstance(value.get("entries"), dict):
        raise AuthThrottleIntegrityError("Enterprise authentication throttle state schema is invalid")
    entries = value["entries"]
    if len(entries) > MAX_AUTH_THROTTLE_BUCKETS:
        raise AuthThrottleIntegrityError("Enterprise authentication throttle state exceeds its bucket limit")
    authenticated = {"schema": AUTH_THROTTLE_SCHEMA, "entries": entries}
    state_key = _auth_state_key(data_key)
    expected = hmac.new(state_key, _canonical(authenticated), hashlib.sha256).hexdigest()
    supplied = str(value.get("mac", ""))
    if len(supplied) != 64 or not hmac.compare_digest(expected, supplied):
        raise AuthThrottleIntegrityError("Enterprise authentication throttle state failed integrity verification")
    now = time.time()
    result: "collections.OrderedDict[str, tuple[int, float]]" = collections.OrderedDict()
    for bucket, row in entries.items():
        if not isinstance(bucket, str) or len(bucket) != 64 or not isinstance(row, dict) or set(row) != {"attempts", "retry_until"}:
            raise AuthThrottleIntegrityError("Enterprise authentication throttle bucket is invalid")
        try:
            attempts = int(row["attempts"])
            retry_until = float(row["retry_until"])
        except (TypeError, ValueError, OverflowError) as exc:
            raise AuthThrottleIntegrityError("Enterprise authentication throttle bucket is invalid") from exc
        if attempts < 0 or attempts > 16 or retry_until < 0:
            raise AuthThrottleIntegrityError("Enterprise authentication throttle bucket is outside its safety bounds")
                                                                                                  
                                                                                         
        retry_until = min(retry_until, now + MAX_AUTH_THROTTLE_DELAY_SECONDS)
        result[bucket] = (attempts, retry_until)
    return result


def save_auth_throttle(path: Path, data_key: bytes, entries: Mapping[str, tuple[int, float]]) -> None:
    ordered = list(entries.items())[-MAX_AUTH_THROTTLE_BUCKETS:]
    serialized: dict[str, dict[str, Any]] = {}
    for bucket, state in ordered:
        attempts, retry_until = state
        if len(str(bucket)) != 64:
            raise ValueError("invalid authentication throttle bucket")
        serialized[str(bucket)] = {
            "attempts": max(0, min(16, int(attempts))),
            "retry_until": max(0.0, float(retry_until)),
        }
    authenticated = {"schema": AUTH_THROTTLE_SCHEMA, "entries": serialized}
    state_key = _auth_state_key(data_key)
    payload = dict(authenticated)
    payload["mac"] = hmac.new(state_key, _canonical(authenticated), hashlib.sha256).hexdigest()
    atomic_write_json(Path(path), payload, ensure_ascii=False, indent=2, mode=0o600)


def auth_bucket_id(data_key: bytes, username: str) -> str:
    return _auth_bucket_id(_auth_state_key(data_key), username)


class BoundedWindowRateLimiter:
    

    def __init__(self, max_buckets: int) -> None:
        self.max_buckets = max(1, int(max_buckets))
        self._lock = threading.Lock()
        self._buckets: "collections.OrderedDict[str, tuple[float, int]]" = collections.OrderedDict()

    def allow(self, key: str, *, limit: int, window_seconds: float = 60.0) -> bool:
        normalized = str(key)[:256] or "unknown"
        now = time.monotonic()
        window = max(1.0, float(window_seconds))
        ceiling = max(1, int(limit))
        with self._lock:
            started, count = self._buckets.get(normalized, (now, 0))
            if now - float(started) >= window:
                started, count = now, 0
            count += 1
            self._buckets[normalized] = (float(started), int(count))
            self._buckets.move_to_end(normalized)
            while len(self._buckets) > self.max_buckets:
                self._buckets.popitem(last=False)
            return count <= ceiling

    def bucket_count(self) -> int:
        with self._lock:
            return len(self._buckets)


def normalize_correlation_id(value: str | None) -> str:
    text = str(value or "").strip()
    if text and len(text) <= MAX_CORRELATION_ID_LENGTH and all(ch in _CORRELATION_CHARS for ch in text):
        return text
    return "corr-" + secrets.token_urlsafe(18)
