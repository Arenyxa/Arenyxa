from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, field, replace
from arenyxa.compat import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, NetworkEvent, RequestSpec, utc_now
from arenyxa.infrastructure.capture.bodies import NetworkBodyStore
from arenyxa.infrastructure.http_client import CancellationToken, HttpFetcher
from arenyxa.infrastructure.observability import Redactor

SIDE_EFFECT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
}
_HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade", "content-length", "host",
}
_SECRET_PATTERN = re.compile(r"^\$\{secret\.[a-z0-9_.-]+\}$", re.I)
_SENSITIVE_PARAMETER = re.compile(
    r"(?:^|[_\-.])(token|secret|password|passwd|api[_-]?key|auth|authorization|session|signature|credential)(?:$|[_\-.])",
    re.I,
)


@dataclass(slots=True)
class ResolvedBody:
    body_ref: str
    payload: bytes
    content_type: str
    encoding: str
    truncated: bool
    sensitive: bool
    sha256: str


class CapturedBodyResolver:
    






    def __init__(self, store: Any, captures_root: Path) -> None:
        self.store = store
        self.captures_root = Path(captures_root)

    def resolve(self, body_ref: str, *, max_bytes: int | None = None) -> ResolvedBody | None:
        artifact = self.store.get_network_body(str(body_ref))
        if artifact is None:
            return None
        session_id = str(artifact.get("session_id") or "")
        if not session_id:
            raise ArenyxaError("REPLAY_BODY_METADATA_INVALID", "捕获正文缺少 Session 标识。", domain="REPLAY")
        body_store = NetworkBodyStore.for_capture(self.captures_root, session_id)
        try:
            payload = body_store.read(artifact, max_bytes=max_bytes)
        except (OSError, ValueError, TypeError) as exc:
            raise ArenyxaError(
                "REPLAY_BODY_INTEGRITY_FAILED",
                "捕获正文完整性验证失败，已拒绝读取。",
                domain="REPLAY",
                context={"body_ref": str(body_ref)},
            ) from exc
        partial_read = max_bytes is not None and int(artifact.get("stored_size") or 0) > max(0, int(max_bytes))
        return ResolvedBody(
            body_ref=str(body_ref),
            payload=payload,
            content_type=str(artifact.get("content_type") or ""),
            encoding=str(artifact.get("encoding") or ""),
            truncated=bool(artifact.get("truncated")) or partial_read,
            sensitive=bool(artifact.get("sensitive")),
            sha256=str(artifact.get("sha256") or ""),
        )

    def load_for_schema(self, body_ref: str, max_bytes: int) -> bytes | None:
        resolved = self.resolve(body_ref, max_bytes=max_bytes)
        if resolved is None or resolved.truncated:
            return None
        return resolved.payload


@dataclass(slots=True)
class ReplayDraft:
    source_event_id: str
    request: RequestSpec
    source_request_id: str | None = None
    session_id: str | None = None
    secret_refs: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    request_body_ref: str | None = None
    request_body_truncated: bool = False
    original_response: FetchResponse | None = None
    request_fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.request_fingerprint:
            self.request_fingerprint = RequestReplayService.request_fingerprint(self.request)


@dataclass(slots=True)
class ReplayResult:
    id: str
    source_request_id: str | None
    session_id: str | None
    method: str
    url: str
    state: str
    started_at: str
    finished_at: str
    response: FetchResponse | None = None
    comparison: dict[str, Any] | None = None
    error_code: str | None = None
    error_message: str | None = None
    request_fingerprint: str = ""


class RequestReplayService:
    def __init__(self, fetcher: HttpFetcher | None = None) -> None:
        self.fetcher = fetcher or HttpFetcher()

    def draft_from_event(self, event: NetworkEvent) -> ReplayDraft:
        if not event.url:
            raise ArenyxaError("REPLAY_NO_URL", "捕获记录没有可重放 URL。", domain="REPLAY")
        headers, secret_refs = self._sanitize_headers(event.request_headers)
        safe_url, secret_query, query_refs, query_warnings = self._sanitize_url_query(event.url)
        secret_refs.update(query_refs)
        warnings: list[str] = list(query_warnings)
        if secret_refs:
            warnings.append("认证/Cookie/敏感 Query 等凭据已替换为 Secret 引用；执行前需要显式绑定。")
        if event.request_body_ref:
            warnings.append("旧 NetworkEvent 仅包含 Body Ref；请从规范化 HTTP Exchange 创建 Draft 以恢复正文。")
        request = RequestSpec(method=event.method or "GET", url=safe_url, query=secret_query, headers=headers)
        return ReplayDraft(
            source_event_id=event.id,
            source_request_id=event.request_ref,
            session_id=event.session_id,
            request=request,
            secret_refs=secret_refs,
            warnings=warnings,
            request_body_ref=event.request_body_ref,
        )

    def draft_from_exchange(
        self,
        exchange: Mapping[str, Any],
        *,
        body_resolver: CapturedBodyResolver | None = None,
        max_request_body_bytes: int = 2 * 1024 * 1024,
    ) -> ReplayDraft:
        url = str(exchange.get("url") or "")
        if not url:
            raise ArenyxaError("REPLAY_NO_URL", "HTTP Exchange 没有可重放 URL。", domain="REPLAY")
        method = str(exchange.get("method") or "GET").upper()
        headers, secret_refs = self._sanitize_headers(exchange.get("request_headers"))
        safe_url, secret_query, query_refs, query_warnings = self._sanitize_url_query(url)
        secret_refs.update(query_refs)
        content_type = self._header(headers, "content-type") or None
        body_ref = str(exchange.get("request_body_ref") or "") or None
        body: str | None = None
        body_truncated = False
        warnings: list[str] = list(query_warnings)
        if secret_refs:
            warnings.append("敏感 Header/Query 已转换为 Secret 引用，不会从捕获记录自动注入明文凭据。")
        if body_ref:
            if body_resolver is None:
                warnings.append("存在请求正文，但未配置 Body Resolver；Draft 不包含正文。")
            else:
                resolved = body_resolver.resolve(body_ref, max_bytes=max_request_body_bytes)
                if resolved is None:
                    warnings.append("请求 Body Ref 在本地 Body Store 中不存在。")
                elif resolved.truncated:
                    body_truncated = True
                    warnings.append("捕获的请求正文被截断；为避免发送不完整写请求，Replay 默认拒绝执行。")
                else:
                    encoding = resolved.encoding or self._charset(resolved.content_type) or "utf-8"
                    try:
                        body = resolved.payload.decode(encoding, errors="strict")
                    except (LookupError, UnicodeDecodeError):
                        try:
                            body = resolved.payload.decode("utf-8", errors="strict")
                        except UnicodeDecodeError:
                            warnings.append("请求正文不是可安全重放的文本 Payload；Draft 未自动加载二进制正文。")
                    content_type = content_type or resolved.content_type or None
        request = RequestSpec(
            url=safe_url, method=method, query=secret_query, headers=headers, body=body, content_type=content_type
        )
        original_response = self.response_from_exchange(exchange, body_resolver=body_resolver)
        return ReplayDraft(
            source_event_id=str(exchange.get("event_id") or exchange.get("request_id") or "captured"),
            source_request_id=str(exchange.get("request_id") or "") or None,
            session_id=str(exchange.get("session_id") or "") or None,
            request=request,
            secret_refs=secret_refs,
            warnings=warnings,
            request_body_ref=body_ref,
            request_body_truncated=body_truncated,
            original_response=original_response,
        )

    def bind_secrets(self, draft: ReplayDraft, secrets: Mapping[str, str]) -> ReplayDraft:
        normalized = {str(key): str(value) for key, value in secrets.items()}

        def resolve(value: str) -> str:
            if not _SECRET_PATTERN.fullmatch(value):
                return value
            if value not in normalized:
                raise ArenyxaError(
                    "REPLAY_SECRET_REQUIRED",
                    f"Replay 需要显式绑定 Secret：{value}",
                    domain="REPLAY",
                    context={"secret_ref": value},
                )
            return normalized[value]

        request = replace(
            draft.request,
            query={key: resolve(value) for key, value in draft.request.query.items()},
            headers={key: resolve(value) for key, value in draft.request.headers.items()},
            cookies={key: resolve(value) for key, value in draft.request.cookies.items()},
            body=resolve(draft.request.body) if isinstance(draft.request.body, str) else draft.request.body,
        )
        return replace(draft, request=request, request_fingerprint=self.request_fingerprint(request))

    def without_secrets(self, draft: ReplayDraft) -> ReplayDraft:
        
        request = replace(
            draft.request,
            query={
                key: value for key, value in draft.request.query.items()
                if not (isinstance(value, str) and _SECRET_PATTERN.fullmatch(value))
            },
            headers={
                key: value for key, value in draft.request.headers.items()
                if not (isinstance(value, str) and _SECRET_PATTERN.fullmatch(value))
            },
            cookies={
                key: value for key, value in draft.request.cookies.items()
                if not (isinstance(value, str) and _SECRET_PATTERN.fullmatch(value))
            },
            body=None if isinstance(draft.request.body, str) and _SECRET_PATTERN.fullmatch(draft.request.body) else draft.request.body,
        )
        warnings = list(draft.warnings)
        if draft.secret_refs:
            warnings.append("已显式选择匿名 Replay；未绑定的敏感 Header/Cookie 不会发送。")
        return replace(
            draft, request=request, secret_refs={}, warnings=warnings,
            request_fingerprint=self.request_fingerprint(request),
        )

    def replay(
        self,
        draft: ReplayDraft,
        *,
        confirm_side_effect: bool = False,
        token: CancellationToken | None = None,
        allow_truncated_body: bool = False,
    ) -> FetchResponse:
        method = draft.request.method.upper()
        if method in SIDE_EFFECT_METHODS and not confirm_side_effect:
            raise ArenyxaError(
                "REPLAY_SIDE_EFFECT_CONFIRMATION",
                f"{method} 可能修改目标系统，需要显式确认。",
                domain="REPLAY",
            )
        if draft.request_body_truncated and not allow_truncated_body:
            raise ArenyxaError(
                "REPLAY_BODY_TRUNCATED",
                "捕获请求正文不完整，默认禁止 Replay。",
                domain="REPLAY",
            )
        unresolved = self.unresolved_secret_refs(draft.request)
        if unresolved:
            raise ArenyxaError(
                "REPLAY_SECRET_REQUIRED",
                "Replay Draft 仍包含未绑定的 Secret 引用。",
                domain="REPLAY",
                context={"secret_refs": unresolved},
            )
        return self.fetcher.fetch(draft.request, token or CancellationToken())

    def execute(
        self,
        draft: ReplayDraft,
        *,
        confirm_side_effect: bool = False,
        token: CancellationToken | None = None,
        allow_truncated_body: bool = False,
    ) -> ReplayResult:
        started_at = utc_now()
        key = f"{draft.source_request_id or draft.source_event_id}\x1f{started_at}\x1f{draft.request_fingerprint}"
        replay_id = "replay_" + hashlib.sha256(key.encode("utf-8", errors="surrogatepass")).hexdigest()[:32]
        try:
            response = self.replay(
                draft,
                confirm_side_effect=confirm_side_effect,
                token=token,
                allow_truncated_body=allow_truncated_body,
            )
            comparison = self.compare(draft.original_response, response) if draft.original_response is not None else None
            return ReplayResult(
                id=replay_id,
                source_request_id=draft.source_request_id,
                session_id=draft.session_id,
                method=draft.request.method.upper(),
                url=draft.request.url,
                state="completed",
                started_at=started_at,
                finished_at=utc_now(),
                response=response,
                comparison=comparison,
                request_fingerprint=draft.request_fingerprint,
            )
        except ArenyxaError as exc:
            return ReplayResult(
                id=replay_id,
                source_request_id=draft.source_request_id,
                session_id=draft.session_id,
                method=draft.request.method.upper(),
                url=draft.request.url,
                state="cancelled" if exc.code == "RUN_CANCELLED" else "failed",
                started_at=started_at,
                finished_at=utc_now(),
                error_code=exc.code,
                error_message=str(exc),
                request_fingerprint=draft.request_fingerprint,
            )
        except Exception as exc:                                                                    
            return ReplayResult(
                id=replay_id,
                source_request_id=draft.source_request_id,
                session_id=draft.session_id,
                method=draft.request.method.upper(),
                url=draft.request.url,
                state="failed",
                started_at=started_at,
                finished_at=utc_now(),
                error_code="REPLAY_UNEXPECTED_ERROR",
                error_message=str(exc),
                request_fingerprint=draft.request_fingerprint,
            )

    @classmethod
    def response_from_exchange(
        cls,
        exchange: Mapping[str, Any],
        *,
        body_resolver: CapturedBodyResolver | None = None,
        max_body_bytes: int = 2 * 1024 * 1024,
    ) -> FetchResponse | None:
        status = exchange.get("status")
        if status is None and not exchange.get("response_id"):
            return None
        body = b""
        body_ref = str(exchange.get("response_body_ref") or "")
        if body_ref and body_resolver is not None:
            resolved = body_resolver.resolve(body_ref, max_bytes=max_body_bytes)
            if resolved is not None and not resolved.truncated:
                body = resolved.payload
        headers = cls._headers(exchange.get("response_headers"))
        content_type = str(exchange.get("content_type") or cls._header(headers, "content-type") or "")
        timing = exchange.get("timing") if isinstance(exchange.get("timing"), Mapping) else {}
        try:
            elapsed = float(timing.get("total_ms", timing.get("har_total_ms", 0.0)))
        except (TypeError, ValueError):
            elapsed = 0.0
        url = str(exchange.get("url") or "")
        return FetchResponse(
            url=url,
            final_url=url,
            status=int(status or 0),
            headers=headers,
            body=body,
            elapsed_ms=max(0.0, elapsed),
            encoding=cls._charset(content_type) or "utf-8",
            content_type=content_type,
        )

    @staticmethod
    def compare(original: FetchResponse, replayed: FetchResponse, *, max_json_changes: int = 128) -> dict[str, Any]:
        def digest(body: bytes) -> str:
            return hashlib.sha256(body).hexdigest()

        content_type_left = original.content_type.split(";", 1)[0].strip().casefold()
        content_type_right = replayed.content_type.split(";", 1)[0].strip().casefold()
        structural: dict[str, Any] | None = None
        json_diff: dict[str, Any] | None = None
        if ("json" in content_type_left or content_type_left.endswith("+json")) and (
            "json" in content_type_right or content_type_right.endswith("+json")
        ):
            try:
                left = json.loads(original.body)
                right = json.loads(replayed.body)
                structural = {
                    "equal": left == right,
                    "left_type": type(left).__name__,
                    "right_type": type(right).__name__,
                }
                json_diff = RequestReplayService._json_diff(left, right, max_changes=max_json_changes)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                structural = None
        return {
            "status": {"before": original.status, "after": replayed.status, "equal": original.status == replayed.status},
            "content_type": {
                "before": original.content_type,
                "after": replayed.content_type,
                "equal": content_type_left == content_type_right,
            },
            "body_hash": {"before": digest(original.body), "after": digest(replayed.body)},
            "body_bytes": {"before": len(original.body), "after": len(replayed.body)},
            "timing_ms": {
                "before": original.elapsed_ms,
                "after": replayed.elapsed_ms,
                "delta": replayed.elapsed_ms - original.elapsed_ms,
            },
            "structural": structural,
            "json_diff": json_diff,
            "headers": RequestReplayService._header_diff(original.headers, replayed.headers),
        }

    @staticmethod
    def request_fingerprint(request: RequestSpec) -> str:
        headers = {
            key.casefold(): ("<secret>" if _SECRET_PATTERN.fullmatch(str(value)) else str(value))
            for key, value in request.headers.items()
            if key.casefold() not in _HOP_BY_HOP_HEADERS
        }
        payload = {
            "method": request.method.upper(),
            "url": request.url,
            "query": request.query,
            "headers": headers,
            "cookies": {key: "<secret>" if _SECRET_PATTERN.fullmatch(str(value)) else str(value) for key, value in request.cookies.items()},
            "body_sha256": hashlib.sha256((request.body or "").encode("utf-8")).hexdigest(),
            "content_type": request.content_type,
            "verify_tls": request.verify_tls,
        }
        return hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8", errors="surrogatepass")
        ).hexdigest()

    @staticmethod
    def unresolved_secret_refs(request: RequestSpec) -> list[str]:
        values = list(request.query.values()) + list(request.headers.values()) + list(request.cookies.values())
        if request.body is not None:
            values.append(request.body)
        return sorted({str(value) for value in values if isinstance(value, str) and _SECRET_PATTERN.fullmatch(value)})

    @staticmethod
    def redacted_request_snapshot(draft: ReplayDraft) -> dict[str, Any]:
        snapshot = asdict(draft.request)
        snapshot["query"] = Redactor().redact(snapshot.get("query", {}))
        snapshot["headers"] = Redactor().redact(snapshot.get("headers", {}))
        snapshot["cookies"] = Redactor().redact(snapshot.get("cookies", {}))
        if snapshot.get("proxy"):
            snapshot["proxy"] = "••••••••"
        if snapshot.get("body") is not None and any(token in str(snapshot.get("body", "")).casefold() for token in ("token", "password", "secret", "api_key", "apikey")):
            snapshot["body"] = "••••••••"
        snapshot["request_fingerprint"] = draft.request_fingerprint
        return snapshot

    @staticmethod
    def response_summary(response: FetchResponse | None) -> dict[str, Any]:
        if response is None:
            return {}
        return {
            "status": response.status,
            "url": response.final_url,
            "content_type": response.content_type,
            "body_bytes": len(response.body),
            "body_sha256": hashlib.sha256(response.body).hexdigest(),
            "elapsed_ms": response.elapsed_ms,
            "headers": Redactor().redact(response.headers),
        }

    @classmethod
    def persistence_record(cls, draft: ReplayDraft, result: ReplayResult) -> dict[str, Any]:
        response = cls.response_summary(result.response)
        return {
            "id": result.id,
            "session_id": result.session_id,
            "source_request_id": result.source_request_id,
            "method": result.method,
            "url": result.url,
            "state": result.state,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "status": result.response.status if result.response is not None else None,
            "elapsed_ms": result.response.elapsed_ms if result.response is not None else None,
            "request_fingerprint": result.request_fingerprint,
            "request": cls.redacted_request_snapshot(draft),
            "response": response,
            "comparison": result.comparison or {},
            "error_code": result.error_code,
            "error_message": result.error_message,
        }

    @staticmethod
    def _sanitize_url_query(url: str) -> tuple[str, dict[str, str], dict[str, str], list[str]]:
        try:
            parts = urlsplit(str(url))
            pairs = parse_qsl(parts.query, keep_blank_values=True)
        except ValueError:
            return str(url), {}, {}, []
        safe_pairs: list[tuple[str, str]] = []
        secret_query: dict[str, str] = {}
        refs: dict[str, str] = {}
        warnings: list[str] = []
        repeated_sensitive: set[str] = set()
        for name, value in pairs:
            if _SENSITIVE_PARAMETER.search(name):
                lowered = re.sub(r"[^a-z0-9_.-]+", "_", name.casefold()) or "query"
                ref = "${secret.query." + lowered + "}"
                if name in secret_query:
                    repeated_sensitive.add(name)
                    continue
                secret_query[name] = ref
                refs[ref] = f"query:{name}"
            else:
                safe_pairs.append((name, value))
        if refs:
            warnings.append("URL 中的敏感 Query 参数已从捕获 URL 移除并转换为 Secret 引用。")
        if repeated_sensitive:
            warnings.append("检测到重复敏感 Query 参数；Replay Draft 仅保留一个显式 Secret 槽位。")
        safe_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(safe_pairs, doseq=True), parts.fragment))
        return safe_url, secret_query, refs, warnings

    @classmethod
    def _sanitize_headers(cls, raw: Any) -> tuple[dict[str, str], dict[str, str]]:
        headers = cls._headers(raw)
        sanitized: dict[str, str] = {}
        refs: dict[str, str] = {}
        for name, value in headers.items():
            lowered = name.casefold().strip()
            if lowered in _HOP_BY_HOP_HEADERS:
                continue
            if lowered in _SENSITIVE_HEADERS or any(token in lowered for token in ("token", "api-key", "apikey", "auth")):
                ref = "${secret.header." + re.sub(r"[^a-z0-9_.-]+", "_", lowered) + "}"
                sanitized[name] = ref
                refs[ref] = f"header:{name}"
            else:
                sanitized[name] = value
        return sanitized, refs

    @staticmethod
    def _headers(raw: Any) -> dict[str, str]:
        if not isinstance(raw, Mapping):
            return {}
        return {str(key): str(value) for key, value in raw.items()}

    @staticmethod
    def _header(headers: Mapping[str, str], name: str) -> str:
        target = name.casefold()
        for key, value in headers.items():
            if key.casefold() == target:
                return str(value)
        return ""

    @staticmethod
    def _charset(content_type: str) -> str:
        for part in str(content_type or "").split(";")[1:]:
            key, separator, value = part.partition("=")
            if separator and key.strip().casefold() == "charset":
                return value.strip().strip('"\'')
        return ""

    @staticmethod
    def _header_diff(left: Mapping[str, str], right: Mapping[str, str]) -> dict[str, Any]:
        volatile = {"date", "age", "server-timing", "x-request-id", "traceparent", "set-cookie"}
        a = {str(key).casefold(): str(value) for key, value in left.items() if str(key).casefold() not in volatile}
        b = {str(key).casefold(): str(value) for key, value in right.items() if str(key).casefold() not in volatile}
        return {
            "added": sorted(key for key in b.keys() - a.keys()),
            "removed": sorted(key for key in a.keys() - b.keys()),
            "changed": sorted(key for key in a.keys() & b.keys() if a[key] != b[key]),
        }

    @staticmethod
    def _json_diff(left: Any, right: Any, *, max_changes: int) -> dict[str, Any]:
        changes: list[dict[str, Any]] = []
        truncated = False

        def walk(a: Any, b: Any, path: str) -> None:
            nonlocal truncated
            if len(changes) >= max(1, int(max_changes)):
                truncated = True
                return
            if type(a) is not type(b):
                changes.append({"path": path or "$", "kind": "type", "before": type(a).__name__, "after": type(b).__name__})
                return
            if isinstance(a, dict):
                for key in sorted(a.keys() - b.keys(), key=str):
                    changes.append({"path": f"{path}.{key}" if path else f"$.{key}", "kind": "removed"})
                    if len(changes) >= max_changes:
                        truncated = True
                        return
                for key in sorted(b.keys() - a.keys(), key=str):
                    changes.append({"path": f"{path}.{key}" if path else f"$.{key}", "kind": "added"})
                    if len(changes) >= max_changes:
                        truncated = True
                        return
                for key in sorted(a.keys() & b.keys(), key=str):
                    walk(a[key], b[key], f"{path}.{key}" if path else f"$.{key}")
                    if truncated:
                        return
                return
            if isinstance(a, list):
                if len(a) != len(b):
                    changes.append({"path": path or "$", "kind": "length", "before": len(a), "after": len(b)})
                for index, (av, bv) in enumerate(zip(a, b)):
                    walk(av, bv, f"{path}[{index}]" if path else f"$[{index}]")
                    if truncated:
                        return
                return
            if a != b:
                before = a if isinstance(a, (str, int, float, bool)) or a is None else repr(a)
                after = b if isinstance(b, (str, int, float, bool)) or b is None else repr(b)
                changes.append({"path": path or "$", "kind": "changed", "before": before, "after": after})

        walk(left, right, "")
        return {"equal": not changes and not truncated, "changes": changes, "truncated": truncated}
