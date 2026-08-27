from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, field
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.proxy_models import ProxyFlow
from arenyxa.infrastructure.capture.proxy_transport import _header, _parse_raw_message


_UUID_OR_ID = re.compile(r"^(?:\d+|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$", re.IGNORECASE)
_SENSITIVE_PARAMETER = re.compile(r"(?:pass|secret|token|key|auth|session|cookie|credential)", re.IGNORECASE)


@dataclass(slots=True)
class ApiEndpointProfile:
    signature: str
    method: str
    scheme: str
    host: str
    path_template: str
    calls: int = 0
    status_families: dict[str, int] = field(default_factory=dict)
    query_parameters: list[dict[str, Any]] = field(default_factory=list)
    authentication: list[str] = field(default_factory=list)
    content_types: list[str] = field(default_factory=list)
    graphql: bool = False
    source: str = "traffic"


@dataclass(slots=True)
class ApiSecurityReport:
    flow_count: int
    endpoint_count: int
    rest_endpoint_count: int
    graphql_endpoint_count: int
    authenticated_endpoint_count: int
    endpoints: list[ApiEndpointProfile]
    token_lifecycle: dict[str, Any]
    findings: list[dict[str, Any]]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class ApiSecurityLab:
    """Passive REST/GraphQL discovery and bounded OpenAPI/Swagger ingestion."""

    MAX_ENDPOINTS = 20_000
    MAX_PARAMETERS = 512

    @staticmethod
    def _path_template(path: str) -> str:
        parts = []
        for part in str(path or "/").split("/"):
            parts.append("{id}" if _UUID_OR_ID.fullmatch(part) else part)
        return "/".join(parts) or "/"

    @staticmethod
    def _auth_schemes(headers: Sequence[tuple[str, str]]) -> set[str]:
        schemes: set[str] = set()
        authorization = _header(list(headers), "Authorization")
        if authorization:
            scheme = authorization.partition(" ")[0].strip().casefold()
            schemes.add(scheme or "authorization")
        if _header(list(headers), "Cookie"):
            schemes.add("cookie")
        for name, _value in headers:
            lowered = str(name).casefold()
            if lowered in {"x-api-key", "api-key"}:
                schemes.add("api-key")
        return schemes

    def _observe_flow(
        self,
        flow: ProxyFlow,
        endpoints: dict[str, dict[str, Any]],
        token_hosts: Counter[str],
        findings: list[dict[str, Any]],
    ) -> tuple[int, int]:
        try:
            _request_line, request_headers, request_body = _parse_raw_message(flow.request_raw)
        except ValueError:
            request_headers, request_body = [], b""
        try:
            _response_line, response_headers, _response_body = _parse_raw_message(flow.response_raw)
        except ValueError:
            response_headers = []
        try:
            parsed = urlsplit(flow.url)
        except ValueError:
            return 0, 0
        path_template = self._path_template(parsed.path)
        method = str(flow.method).upper()
        signature = f"{method} {parsed.scheme}://{parsed.netloc}{path_template}"
        auth = self._auth_schemes(request_headers)
        content_type = _header(request_headers, "Content-Type").split(";", 1)[0].casefold()
        response_type = _header(response_headers, "Content-Type").split(";", 1)[0].casefold()
        graphql = "graphql" in parsed.path.casefold() or (
            "json" in content_type and b'"query"' in request_body[:1024 * 1024]
        )
        state = endpoints.setdefault(signature, {
            "method": method,
            "scheme": parsed.scheme or flow.scheme,
            "host": parsed.hostname or flow.host,
            "path_template": path_template,
            "calls": 0,
            "statuses": Counter(),
            "parameters": defaultdict(lambda: {"occurrences": 0, "sensitive": False}),
            "authentication": set(),
            "content_types": set(),
            "graphql": graphql,
            "source": "traffic",
        })
        state["calls"] += 1
        family = f"{int(flow.status) // 100}xx" if isinstance(flow.status, int) and 100 <= flow.status <= 599 else "other"
        state["statuses"][family] += 1
        state["authentication"].update(auth)
        state["graphql"] = bool(state["graphql"] or graphql)
        state["content_types"].update(value for value in (content_type, response_type) if value)
        query = parse_qsl(parsed.query, keep_blank_values=True)[: self.MAX_PARAMETERS]
        for name, _value in query:
            parameter = state["parameters"][name]
            parameter["occurrences"] += 1
            parameter["sensitive"] = bool(parameter["sensitive"] or _SENSITIVE_PARAMETER.search(name))
        if auth:
            token_hosts[str(parsed.hostname or flow.host)] += 1
        if parsed.scheme == "http" and auth:
            findings.append({
                "severity": "high",
                "kind": "plaintext-authentication",
                "endpoint": signature,
                "detail": "Authentication metadata was observed over plaintext HTTP.",
            })
        sensitive_query = sorted(name for name, _value in query if _SENSITIVE_PARAMETER.search(name))
        if sensitive_query:
            findings.append({
                "severity": "medium",
                "kind": "sensitive-query-parameter",
                "endpoint": signature,
                "parameter_names": sensitive_query[:64],
            })
        return int(bool(_header(response_headers, "Set-Cookie"))), int(bool(auth))

    def analyze(self, flows: Sequence[ProxyFlow]) -> ApiSecurityReport:
        endpoints: dict[str, dict[str, Any]] = {}
        token_issued = 0
        token_used = 0
        token_hosts: Counter[str] = Counter()
        findings: list[dict[str, Any]] = []
        for flow in flows:
            if len(endpoints) >= self.MAX_ENDPOINTS:
                break
            issued, used = self._observe_flow(flow, endpoints, token_hosts, findings)
            token_issued += issued
            token_used += used

        profiles: list[ApiEndpointProfile] = []
        for signature, state in sorted(endpoints.items(), key=lambda item: (-item[1]["calls"], item[0])):
            parameters = [
                {"name": name, **value}
                for name, value in sorted(state["parameters"].items())[: self.MAX_PARAMETERS]
            ]
            profiles.append(ApiEndpointProfile(
                signature=signature,
                method=state["method"],
                scheme=state["scheme"],
                host=state["host"],
                path_template=state["path_template"],
                calls=int(state["calls"]),
                status_families=dict(state["statuses"]),
                query_parameters=parameters,
                authentication=sorted(state["authentication"]),
                content_types=sorted(state["content_types"]),
                graphql=bool(state["graphql"]),
                source=state["source"],
            ))
        return ApiSecurityReport(
            flow_count=len(flows),
            endpoint_count=len(profiles),
            rest_endpoint_count=sum(1 for item in profiles if not item.graphql),
            graphql_endpoint_count=sum(1 for item in profiles if item.graphql),
            authenticated_endpoint_count=sum(1 for item in profiles if item.authentication),
            endpoints=profiles,
            token_lifecycle={
                "issuance_observations": token_issued,
                "use_observations": token_used,
                "hosts": [{"host": host, "uses": count} for host, count in token_hosts.most_common(100)],
            },
            findings=findings[:2_000],
        )

    def import_openapi(self, document: Mapping[str, Any]) -> list[ApiEndpointProfile]:
        """Import OpenAPI 2/3 paths without resolving remote references."""
        if not isinstance(document, Mapping):
            raise ValueError("OpenAPI document must be an object")
        if not (document.get("openapi") or document.get("swagger")):
            raise ValueError("OpenAPI or Swagger version marker is required")
        paths = document.get("paths")
        if not isinstance(paths, Mapping):
            raise ValueError("OpenAPI paths must be an object")
        servers = document.get("servers")
        base_url = ""
        if isinstance(servers, list) and servers and isinstance(servers[0], Mapping):
            base_url = str(servers[0].get("url") or "")
        if not base_url and document.get("host"):
            schemes = document.get("schemes")
            scheme = str(schemes[0]) if isinstance(schemes, list) and schemes else "https"
            base_url = f"{scheme}://{document.get('host')}{document.get('basePath') or ''}"
        base = urlsplit(base_url or "https://openapi.local")
        rows: list[ApiEndpointProfile] = []
        for path, operations in paths.items():
            if len(rows) >= self.MAX_ENDPOINTS or not isinstance(operations, Mapping):
                break
            for method, operation in operations.items():
                if str(method).casefold() not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}:
                    continue
                operation_map = operation if isinstance(operation, Mapping) else {}
                security = operation_map.get("security", document.get("security", []))
                auth = sorted(
                    str(name)
                    for item in security if isinstance(item, Mapping)
                    for name in item.keys()
                ) if isinstance(security, list) else []
                full_path = (base.path.rstrip("/") + "/" + str(path).lstrip("/")) or "/"
                signature = f"{str(method).upper()} {base.scheme}://{base.netloc}{full_path}"
                parameters = operation_map.get("parameters", [])
                rows.append(ApiEndpointProfile(
                    signature=signature,
                    method=str(method).upper(),
                    scheme=base.scheme,
                    host=base.hostname or "openapi.local",
                    path_template=full_path,
                    query_parameters=[
                        {"name": str(item.get("name") or ""), "location": str(item.get("in") or "")}
                        for item in parameters[: self.MAX_PARAMETERS] if isinstance(item, Mapping)
                    ] if isinstance(parameters, list) else [],
                    authentication=auth,
                    graphql=False,
                    source="openapi",
                ))
        return rows

    def import_openapi_json(self, text: str) -> list[ApiEndpointProfile]:
        value = json.loads(str(text))
        if not isinstance(value, Mapping):
            raise ValueError("OpenAPI document must be a JSON object")
        return self.import_openapi(value)


__all__ = ["ApiEndpointProfile", "ApiSecurityLab", "ApiSecurityReport"]
