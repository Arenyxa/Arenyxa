from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional
from urllib.parse import parse_qsl, urlsplit

from arenyxa.domain.models import utc_now

BodyLoader = Callable[[str, int], Optional[bytes]]

_PAGINATION_NAMES = {
    "page", "pageindex", "page_index", "pagenumber", "page_number", "offset", "limit",
    "cursor", "after", "before", "first", "last", "per_page", "pagesize", "page_size",
    "continuation", "continuationtoken", "continuation_token", "next", "skip", "take",
}
_SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
}
_SENSITIVE_PARAMETER = re.compile(
    r"(?:^|[_\-.])(token|secret|password|passwd|api[_-]?key|auth|authorization|session|signature|credential)(?:$|[_\-.])",
    re.I,
)
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I
)
_HEX_SEGMENT = re.compile(r"^[0-9a-f]{12,64}$", re.I)
_INTEGER_SEGMENT = re.compile(r"^-?\d+$")
_ULID_SEGMENT = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$", re.I)


@dataclass(slots=True)
class ParameterProfile:
    name: str
    present_count: int
    sample_count: int
    required_ratio: float
    value_types: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    pagination_candidate: bool = False
    sensitive: bool = False


@dataclass(slots=True)
class ApiEndpoint:
    id: str
    method: str
    host: str
    path: str
    scheme: str
    samples: int
    statuses: list[int]
    success_rate: float
    query_parameters: list[ParameterProfile]
    pagination_candidates: list[str]
    request_content_types: list[str]
    response_content_types: list[str]
    auth_signals: list[str]
    graphql: bool
    api_likelihood: float
    confidence: float
    risk_level: str
    replay_safe_by_default: bool
    sample_request_ids: list[str]
    response_schema: dict[str, Any] | None = None
    schema_fingerprint: str | None = None


@dataclass(slots=True)
class ApiMapSnapshot:
    id: str
    session_id: str
    created_at: str
    endpoint_count: int
    source_event_count: int
    endpoints: list[ApiEndpoint]
    host_count: int
    graphql_endpoint_count: int
    pagination_endpoint_count: int
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ApiMapService:
    






    def __init__(
        self,
        *,
        max_exchanges: int = 100_000,
        max_schema_body_bytes: int = 1024 * 1024,
        max_schema_total_bytes: int = 8 * 1024 * 1024,
        max_examples_per_parameter: int = 3,
        max_schema_depth: int = 5,
        max_schema_keys: int = 128,
    ) -> None:
        self.max_exchanges = max(1, min(int(max_exchanges), 100_000))
        self.max_schema_body_bytes = max(1024, min(int(max_schema_body_bytes), 8 * 1024 * 1024))
        self.max_schema_total_bytes = max(
            self.max_schema_body_bytes,
            min(int(max_schema_total_bytes), 64 * 1024 * 1024),
        )
        self.max_examples_per_parameter = max(0, min(int(max_examples_per_parameter), 8))
        self.max_schema_depth = max(1, min(int(max_schema_depth), 8))
        self.max_schema_keys = max(8, min(int(max_schema_keys), 512))

    def build(
        self,
        session_id: str,
        exchanges: Iterable[Mapping[str, Any]],
        *,
        body_loader: BodyLoader | None = None,
    ) -> ApiMapSnapshot:
        grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        source_count = 0
        warnings: list[str] = []
        for raw in exchanges:
            if source_count >= self.max_exchanges:
                warnings.append(f"API Map 已达到 {self.max_exchanges:,} 条 Exchange 上限，剩余记录未分析。")
                break
            source_count += 1
            exchange = dict(raw)
            url = str(exchange.get("url") or "")
            method = str(exchange.get("method") or "GET").upper()
            try:
                parsed = urlsplit(url)
                host = (parsed.hostname or str(exchange.get("host") or "")).casefold()
            except ValueError:
                continue
            if parsed.scheme.casefold() not in {"http", "https"} or not host:
                continue
            path = self.normalize_path(parsed.path or "/")
            grouped[(method, parsed.scheme.casefold(), host, path)].append(exchange)

        schema_budget = self.max_schema_total_bytes
        endpoints: list[ApiEndpoint] = []
        for (method, scheme, host, path), records in grouped.items():
            endpoint, consumed = self._build_endpoint(
                method,
                scheme,
                host,
                path,
                records,
                body_loader=body_loader,
                schema_budget=schema_budget,
            )
            schema_budget = max(0, schema_budget - consumed)
            endpoints.append(endpoint)

        endpoints.sort(key=lambda item: (-item.api_likelihood, -item.samples, item.host, item.path, item.method))
        snapshot_key = json.dumps(
            [
                (item.id, item.samples, item.statuses, item.schema_fingerprint)
                for item in endpoints
            ],
            ensure_ascii=False,
            sort_keys=True,
        )
        snapshot_id = "apimap_" + hashlib.sha256(
            f"{session_id}\x1f{snapshot_key}".encode("utf-8", errors="surrogatepass")
        ).hexdigest()[:32]
        return ApiMapSnapshot(
            id=snapshot_id,
            session_id=str(session_id),
            created_at=utc_now(),
            endpoint_count=len(endpoints),
            source_event_count=source_count,
            endpoints=endpoints,
            host_count=len({item.host for item in endpoints}),
            graphql_endpoint_count=sum(1 for item in endpoints if item.graphql),
            pagination_endpoint_count=sum(1 for item in endpoints if item.pagination_candidates),
            warnings=warnings,
        )

    def _build_endpoint(
        self,
        method: str,
        scheme: str,
        host: str,
        path: str,
        records: list[dict[str, Any]],
        *,
        body_loader: BodyLoader | None,
        schema_budget: int,
    ) -> tuple[ApiEndpoint, int]:
        sample_count = len(records)
        statuses = sorted({int(item["status"]) for item in records if item.get("status") is not None})
        success_count = sum(1 for item in records if self._is_success(item.get("status")))
        success_rate = round(success_count / sample_count, 4) if sample_count else 0.0

        query_values: dict[str, list[str]] = defaultdict(list)
        query_presence: Counter[str] = Counter()
        request_content_types: set[str] = set()
        response_content_types: set[str] = set()
        auth_signals: set[str] = set()
        sample_request_ids: list[str] = []
        json_like = False
        graphql = path.casefold().endswith("/graphql") or path.casefold() == "/graphql"
        schema_samples: list[Any] = []
        consumed = 0

        for record in records:
            request_id = str(record.get("request_id") or record.get("event_id") or "")
            if request_id and request_id not in sample_request_ids and len(sample_request_ids) < 8:
                sample_request_ids.append(request_id)
            url = str(record.get("url") or "")
            try:
                pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
            except ValueError:
                pairs = []
            seen: set[str] = set()
            for key, value in pairs:
                key = str(key)
                query_values[key].append(str(value))
                seen.add(key)
            raw_query = record.get("query")
            if isinstance(raw_query, Mapping):
                for key, values in raw_query.items():
                    key = str(key)
                    if key in seen:
                        continue
                    if isinstance(values, (list, tuple)):
                        query_values[key].extend(str(value) for value in values)
                    else:
                        query_values[key].append(str(values))
                    seen.add(key)
            query_presence.update(seen)

            request_headers = self._headers(record.get("request_headers"))
            response_headers = self._headers(record.get("response_headers"))
            req_ct = self._media_type(self._header(request_headers, "content-type"))
            rsp_ct = self._media_type(str(record.get("content_type") or self._header(response_headers, "content-type")))
            if req_ct:
                request_content_types.add(req_ct)
            if rsp_ct:
                response_content_types.add(rsp_ct)
            if "json" in rsp_ct or rsp_ct.endswith("+json"):
                json_like = True
            for name in request_headers:
                if name.casefold() in _SENSITIVE_HEADERS or any(
                    token in name.casefold() for token in ("token", "api-key", "apikey", "auth")
                ):
                    auth_signals.add(name.casefold())

            if graphql or ("json" in req_ct and body_loader is not None):
                body_ref = record.get("request_body_ref")
                if body_ref and body_loader is not None and schema_budget > 0:
                    raw = body_loader(str(body_ref), min(self.max_schema_body_bytes, schema_budget))
                    if raw:
                        consumed += len(raw)
                        schema_budget -= len(raw)
                        graphql = graphql or self._body_looks_graphql(raw)

            if body_loader is not None and schema_budget > 0 and ("json" in rsp_ct or rsp_ct.endswith("+json")):
                body_ref = record.get("response_body_ref")
                if body_ref:
                    raw = body_loader(str(body_ref), min(self.max_schema_body_bytes, schema_budget))
                    if raw:
                        consumed += len(raw)
                        schema_budget -= len(raw)
                        try:
                            schema_samples.append(json.loads(raw.decode("utf-8", errors="strict")))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            record_current_exception(__name__, 'ApiMapService._build_endpoint:275')

        profiles: list[ParameterProfile] = []
        for name in sorted(query_presence):
            values = query_values.get(name, [])
            unique_examples: list[str] = []
            for value in values:
                if value not in unique_examples:
                    unique_examples.append(value)
                if len(unique_examples) >= self.max_examples_per_parameter:
                    break
            sensitive_parameter = bool(_SENSITIVE_PARAMETER.search(name))
            profiles.append(
                ParameterProfile(
                    name=name,
                    present_count=int(query_presence[name]),
                    sample_count=sample_count,
                    required_ratio=round(query_presence[name] / sample_count, 4),
                    value_types=sorted({self._value_type(value) for value in values}),
                    examples=[] if sensitive_parameter else unique_examples,
                    pagination_candidate=name.casefold() in _PAGINATION_NAMES,
                    sensitive=sensitive_parameter,
                )
            )
        pagination = [item.name for item in profiles if item.pagination_candidate]

        response_schema = self._merge_schema_samples(schema_samples) if schema_samples else None
        schema_fingerprint = None
        if response_schema is not None:
            schema_fingerprint = hashlib.sha256(
                json.dumps(response_schema, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()

        likelihood = 0.12
        lowered_path = path.casefold()
        if "/api/" in lowered_path or lowered_path.startswith("/api/"):
            likelihood += 0.34
        if graphql:
            likelihood += 0.42
        if json_like:
            likelihood += 0.34
        if request_content_types and any("json" in value for value in request_content_types):
            likelihood += 0.08
        if auth_signals:
            likelihood += 0.04
        likelihood = round(min(1.0, likelihood), 4)
        confidence = round(
            min(1.0, likelihood * 0.65 + min(0.22, math.log2(sample_count + 1) * 0.055) + (0.1 if statuses else 0.0)),
            4,
        )
        risk_level = "write" if method in {"POST", "PUT", "PATCH", "DELETE"} else "read"
        endpoint_id = "endpoint_" + hashlib.sha256(
            f"{method}\x1f{scheme}\x1f{host}\x1f{path}".encode("utf-8", errors="surrogatepass")
        ).hexdigest()[:32]
        return (
            ApiEndpoint(
                id=endpoint_id,
                method=method,
                host=host,
                path=path,
                scheme=scheme,
                samples=sample_count,
                statuses=statuses,
                success_rate=success_rate,
                query_parameters=profiles,
                pagination_candidates=pagination,
                request_content_types=sorted(request_content_types),
                response_content_types=sorted(response_content_types),
                auth_signals=sorted(auth_signals),
                graphql=graphql,
                api_likelihood=likelihood,
                confidence=confidence,
                risk_level=risk_level,
                replay_safe_by_default=(
                    method in {"GET", "HEAD", "OPTIONS"}
                    and not auth_signals
                    and not any(item.sensitive for item in profiles)
                ),
                sample_request_ids=sample_request_ids,
                response_schema=response_schema,
                schema_fingerprint=schema_fingerprint,
            ),
            consumed,
        )

    @classmethod
    def normalize_path(cls, path: str) -> str:
        if not path:
            return "/"
        segments = path.split("/")
        normalized: list[str] = []
        for segment in segments:
            if not segment:
                normalized.append("")
            elif _UUID_SEGMENT.fullmatch(segment):
                normalized.append("{uuid}")
            elif _INTEGER_SEGMENT.fullmatch(segment):
                normalized.append("{id}")
            elif _HEX_SEGMENT.fullmatch(segment) or _ULID_SEGMENT.fullmatch(segment):
                normalized.append("{id}")
            else:
                normalized.append(segment)
        result = "/".join(normalized)
        return result if result.startswith("/") else "/" + result

    def _merge_schema_samples(self, samples: list[Any]) -> dict[str, Any] | None:
        schemas = [self._schema(value, depth=0, key_budget=[self.max_schema_keys]) for value in samples]
        schemas = [schema for schema in schemas if schema is not None]
        if not schemas:
            return None
        merged = schemas[0]
        for schema in schemas[1:]:
            merged = self._merge_schema(merged, schema)
        return merged

    def _schema(self, value: Any, *, depth: int, key_budget: list[int]) -> dict[str, Any] | None:
        if depth >= self.max_schema_depth:
            return {"type": self._json_type(value), "truncated": True}
        if isinstance(value, dict):
            properties: dict[str, Any] = {}
            for key in sorted(value):
                if key_budget[0] <= 0:
                    break
                key_budget[0] -= 1
                properties[str(key)] = self._schema(value[key], depth=depth + 1, key_budget=key_budget)
            schema: dict[str, Any] = {"type": "object", "properties": properties}
            if len(properties) < len(value):
                schema["truncated"] = True
            return schema
        if isinstance(value, list):
            item_schemas = [self._schema(item, depth=depth + 1, key_budget=key_budget) for item in value[:8]]
            item_schemas = [item for item in item_schemas if item is not None]
            merged = item_schemas[0] if item_schemas else {"type": "unknown"}
            for item in item_schemas[1:]:
                merged = self._merge_schema(merged, item)
            return {"type": "array", "items": merged}
        return {"type": self._json_type(value)}

    @classmethod
    def _merge_schema(cls, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
        if left == right:
            return left
        left_type = left.get("type")
        right_type = right.get("type")
        if left_type == right_type == "object":
            left_props = dict(left.get("properties") or {})
            right_props = dict(right.get("properties") or {})
            merged_props: dict[str, Any] = {}
            for key in sorted(set(left_props) | set(right_props)):
                if key in left_props and key in right_props:
                    merged_props[key] = cls._merge_schema(left_props[key], right_props[key])
                else:
                    source = left_props if key in left_props else right_props
                    merged_props[key] = {**source[key], "optional": True}
            result: dict[str, Any] = {"type": "object", "properties": merged_props}
            if left.get("truncated") or right.get("truncated"):
                result["truncated"] = True
            return result
        if left_type == right_type == "array":
            return {"type": "array", "items": cls._merge_schema(left.get("items", {}), right.get("items", {}))}
        types: set[str] = set()
        for value in (left_type, right_type):
            if isinstance(value, list):
                types.update(str(item) for item in value)
            elif value:
                types.add(str(value))
        return {"type": sorted(types) if types else ["unknown"]}

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
    def _media_type(value: str) -> str:
        return str(value or "").split(";", 1)[0].strip().casefold()

    @staticmethod
    def _is_success(status: Any) -> bool:
        try:
            value = int(status)
        except (TypeError, ValueError):
            return False
        return 200 <= value < 400

    @staticmethod
    def _value_type(value: str) -> str:
        lowered = value.casefold()
        if lowered in {"true", "false"}:
            return "boolean"
        try:
            int(value)
            return "integer"
        except ValueError:
            try:
                float(value)
                return "number"
            except ValueError:
                return "string"

    @staticmethod
    def _body_looks_graphql(raw: bytes) -> bool:
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        return isinstance(value, dict) and isinstance(value.get("query"), str)

    @staticmethod
    def _json_type(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, list):
            return "array"
        if isinstance(value, dict):
            return "object"
        return "unknown"
