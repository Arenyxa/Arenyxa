from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import logging
import ssl
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from arenyxa.domain.errors import ArenyxaError
from arenyxa.observability.trace_context import TraceContext, trace_context_from_headers
from arenyxa.observability.otel_bridge import configure_otel_from_env, server_span
from arenyxa.enterprise.transport_security import BoundedWindowRateLimiter, normalize_correlation_id
from arenyxa.enterprise.distributed import (
    CURRENT_PROTOCOL,
    DEFAULT_LEASE_SECONDS,
    MAX_CHECKPOINT_BYTES,
    MAX_JOB_PAYLOAD_BYTES,
    MAX_RESULT_BYTES,
    MAX_WORKER_SLOTS,
    EnterpriseServerRuntime,
    DistributedLease,
    verify_enterprise_server_identity,
)

MAX_API_BODY_BYTES = max(MAX_JOB_PAYLOAD_BYTES, MAX_RESULT_BYTES, MAX_CHECKPOINT_BYTES) + 64 * 1024
MAX_SERVER_RATE_BUCKETS = 4096
MAX_SERVER_REQUESTS_PER_MINUTE = 600
MAX_SERVER_AUTH_REQUESTS_PER_MINUTE = 60
MAX_SERVER_INFLIGHT_REQUESTS = 256
CORRELATION_HEADER = "x-arenyxa-correlation-id"
LOGGER = logging.getLogger(__name__)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _json_object_no_duplicates(raw: bytes) -> dict[str, Any]:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=hook) if raw else {}
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON body must be an object")
    return value


def _lease_dict(lease: DistributedLease | None) -> dict[str, Any] | None:
    if lease is None:
        return None
    return asdict(lease)


def _zero_trust_denial(runtime: EnterpriseServerRuntime, request: Any, peer: str, transport: str) -> str | None:
    authorization = str(request.headers.get("authorization", ""))
    if not authorization.startswith("Bearer "):
        return None
    if request.url.path in {"/enterprise/v1/worker/challenge", "/enterprise/v1/worker/auth"}:
        return None
    token = authorization[7:].strip()
    if not token:
        return None
    try:
        runtime.authorize_worker_session_context(
            token,
            {
                "source_ip": peer,
                "transport": transport,
                "via_server_relay": True,
                "peer_to_peer": False,
                "network_trust": "private" if peer not in {"unknown", ""} else "unknown",
                "risk_score": 0,
                "auth_age_seconds": 0,
            },
        )
    except ArenyxaError as exc:
        return exc.code
    return None


async def _request_body_error(request: Any) -> tuple[int, str] | None:
    if str(request.method).upper() not in {"POST", "PUT", "PATCH"}:
        return None
    if request.headers.get("transfer-encoding"):
        return 400, "transfer-encoding is not supported"
    raw_length = request.headers.get("content-length", "")
    if not raw_length:
        return 411, "content-length required"
    try:
        length = int(raw_length)
    except ValueError:
        return 400, "invalid content-length"
    if length < 0:
        return 400, "invalid content-length"
    if length > MAX_API_BODY_BYTES:
        return 413, "request body too large"
    raw = await request.body()
    if len(raw) != length:
        return 400, "content-length mismatch"
    if len(raw) > MAX_API_BODY_BYTES:
        return 413, "request body too large"
    if raw:
        try:
            _json_object_no_duplicates(raw)
        except ValueError:
            return 400, "invalid or duplicate-key JSON"
    return None


def _enterprise_server_helpers(server_identity: Any, http_exception: Any) -> tuple[Any, Any, Any]:
    """Build lightweight request helpers without extending the FastAPI factory body."""
    def current_identity() -> dict[str, Any]:
        value = server_identity() if callable(server_identity) else server_identity
        if not isinstance(value, Mapping):
            raise RuntimeError("Enterprise Server identity provider returned an invalid artifact")
        return dict(value)

    def worker_token(authorization: str) -> str:
        if not authorization.startswith("Bearer "):
            raise http_exception(status_code=401, detail="worker authentication required")
        token = authorization[7:].strip()
        if not token:
            raise http_exception(status_code=401, detail="worker authentication required")
        return token

    def bounded_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise http_exception(status_code=400, detail=f"invalid {label}") from exc
        if parsed < minimum or parsed > maximum:
            raise http_exception(status_code=400, detail=f"{label} outside supported range")
        return parsed

    return current_identity, worker_token, bounded_int


class _ServerTrafficMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total = 0
        self._active = 0
        self._peak_active = 0
        self._status_2xx = 0
        self._status_4xx = 0
        self._status_5xx = 0
        self._rate_rejected = 0
        self._capacity_rejected = 0

    def accepted(self) -> None:
        with self._lock:
            self._total += 1
            self._active += 1
            self._peak_active = max(self._peak_active, self._active)

    def rejected(self, reason: str) -> None:
        with self._lock:
            self._total += 1
            if reason == "rate":
                self._rate_rejected += 1
            elif reason == "capacity":
                self._capacity_rejected += 1

    def finished(self, status: int) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)
            if 200 <= int(status) < 300:
                self._status_2xx += 1
            elif 400 <= int(status) < 500:
                self._status_4xx += 1
            elif int(status) >= 500:
                self._status_5xx += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "requests_total": self._total,
                "inflight_current": self._active,
                "inflight_peak": self._peak_active,
                "responses_2xx": self._status_2xx,
                "responses_4xx": self._status_4xx,
                "responses_5xx": self._status_5xx,
                "rate_rejected": self._rate_rejected,
                "capacity_rejected": self._capacity_rejected,
            }


def create_enterprise_server_app(runtime: EnterpriseServerRuntime, server_identity: Any) -> Any:
    try:
        from fastapi import FastAPI, Header, HTTPException, Request
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise RuntimeError("Enterprise Server mode requires: pip install -e .[server]") from exc

    current_identity, worker_token, bounded_int = _enterprise_server_helpers(server_identity, HTTPException)

    configure_otel_from_env("arenyxa-enterprise-server")
    app = FastAPI(title="Arenyxa Enterprise Worker Service", version=str(CURRENT_PROTOCOL))
    peer_limiter = BoundedWindowRateLimiter(MAX_SERVER_RATE_BUCKETS)
    auth_limiter = BoundedWindowRateLimiter(MAX_SERVER_RATE_BUCKETS)
    inflight_slots = threading.BoundedSemaphore(MAX_SERVER_INFLIGHT_REQUESTS)
    traffic_metrics = _ServerTrafficMetrics()
    @app.middleware("http")
    async def transport_guard(request: Request, call_next: Any) -> Any:
        correlation_id = normalize_correlation_id(request.headers.get(CORRELATION_HEADER))
        trace_context = trace_context_from_headers(request.headers, correlation_id=correlation_id)
        request.state.correlation_id = correlation_id
        request.state.trace_context = trace_context
        peer = str(getattr(request.client, "host", "") or "unknown")[:128]
        transport = "tls13" if str(request.url.scheme).casefold() == "https" else "local" if peer in {"127.0.0.1", "::1"} else ""

        def finalize(response: Any) -> Any:
            response.headers[CORRELATION_HEADER] = correlation_id
            response.headers["traceparent"] = trace_context.traceparent
            if trace_context.tracestate:
                response.headers["tracestate"] = trace_context.tracestate
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response

        if not peer_limiter.allow(peer, limit=MAX_SERVER_REQUESTS_PER_MINUTE):
            traffic_metrics.rejected("rate")
            return finalize(JSONResponse(status_code=429, content={"detail": "request rate limit exceeded"}))
        if request.url.path in {"/enterprise/v1/worker/challenge", "/enterprise/v1/worker/auth"}:
            if not auth_limiter.allow(peer, limit=MAX_SERVER_AUTH_REQUESTS_PER_MINUTE):
                traffic_metrics.rejected("rate")
                return finalize(JSONResponse(status_code=429, content={"detail": "authentication rate limit exceeded"}))
        denial = _zero_trust_denial(runtime, request, peer, transport)
        if denial is not None:
            traffic_metrics.rejected("rate")
            return finalize(JSONResponse(status_code=403, content={"detail": denial}))
        if not inflight_slots.acquire(blocking=False):
            traffic_metrics.rejected("capacity")
            return finalize(JSONResponse(status_code=503, content={"detail": "server request capacity exhausted"}))
        traffic_metrics.accepted()
        status = 500
        try:
                                                                                                 
                                                                                                    
                                                                                    
            with server_span(
                f"{request.method} {request.url.path}",
                trace_context,
                {
                    "http.request.method": str(request.method),
                    "url.path": str(request.url.path)[:256],
                    "client.address": peer,
                    "arenyxa.correlation_id": correlation_id,
                },
            ):
                body_error = await _request_body_error(request)
                if body_error is not None:
                    error_status, detail = body_error
                    response = JSONResponse(status_code=error_status, content={"detail": detail})
                    status = response.status_code
                    return finalize(response)
                response = await call_next(request)
                status = int(getattr(response, "status_code", 500))
                return finalize(response)
        finally:
            inflight_slots.release()
            traffic_metrics.finished(status)
            LOGGER.info(
                "enterprise worker protocol request",
                extra={
                    "correlation_id": correlation_id,
                    "trace_id": trace_context.trace_id,
                    "span_id": trace_context.span_id,
                    "parent_span_id": trace_context.parent_span_id,
                    "phase": "enterprise-server-http",
                    "resource_id": request.url.path[:256],
                    "error_code": "" if status < 400 else f"HTTP_{status}",
                },
            )

    @app.exception_handler(ArenyxaError)
    async def enterprise_error(_request: Request, exc: ArenyxaError) -> Any:
        status = 409
        if exc.code in {"WORKER_UNKNOWN", "DISTRIBUTED_JOB_UNKNOWN"}:
            status = 404
        elif exc.code in {"WORKER_REVOKED", "WORKER_SESSION_INVALID", "WORKER_PROOF_INVALID", "WORKER_CHALLENGE_INVALID"}:
            status = 403
        elif exc.code in {"DISTRIBUTED_LEASE_STALE", "DISTRIBUTED_LEASE_EXPIRED"}:
            status = 409
        elif exc.code in {"DISTRIBUTED_PAYLOAD_TOO_LARGE"}:
            status = 413
        return JSONResponse(status_code=status, content={"detail": exc.code})

    @app.get("/enterprise/v1/identity")
    def get_identity() -> dict[str, Any]:
        return current_identity()

    @app.get("/enterprise/v1/live")
    def live() -> dict[str, Any]:
        return {"live": True, "protocol": CURRENT_PROTOCOL}

    @app.get("/enterprise/v1/ready")
    def ready() -> Any:
        payload = dict(runtime.queue.health())
        invariants = dict(payload.get("state_invariants") or {})
        invariant_failures = {
            key: int(value) for key, value in invariants.items()
            if isinstance(value, (int, float)) and int(value) != 0
        }
        ready_state = bool(payload.get("healthy", True)) and not invariant_failures
        capacity = dict(payload.get("capacity") or {})
        body = {
            "ready": ready_state,
            "degraded": str(capacity.get("severity") or "healthy").casefold() == "critical",
            "protocol": CURRENT_PROTOCOL,
            "storage": payload.get("storage"),
            "capacity": capacity,
            "deployment_profile": payload.get("deployment_profile"),
            "state_invariants": invariants,
            "invariant_failures": invariant_failures,
        }
        return JSONResponse(status_code=200 if ready_state else 503, content=body)

    @app.get("/enterprise/v1/health")
    def health() -> dict[str, Any]:
        payload = dict(runtime.queue.health())
        payload["transport_security"] = {
            "peer_rate_buckets": peer_limiter.bucket_count(),
            "auth_rate_buckets": auth_limiter.bucket_count(),
            "peer_rate_state": peer_limiter.snapshot(),
            "auth_rate_state": auth_limiter.snapshot(),
            "max_requests_per_minute": MAX_SERVER_REQUESTS_PER_MINUTE,
            "max_auth_requests_per_minute": MAX_SERVER_AUTH_REQUESTS_PER_MINUTE,
            "max_inflight_requests": MAX_SERVER_INFLIGHT_REQUESTS,
            "correlation_header": CORRELATION_HEADER,
            "tls_minimum_default": "TLSv1.3",
            "tls12_compatibility": "explicit operator opt-in",
            "traffic_metrics": traffic_metrics.snapshot(),
        }
        return payload

    @app.post("/enterprise/v1/worker/challenge")
    def challenge(body: dict[str, Any]) -> dict[str, Any]:
        return runtime.create_worker_challenge(str(body.get("worker_id", "")))

    @app.post("/enterprise/v1/worker/auth")
    def authenticate(body: dict[str, Any], request: Request) -> dict[str, Any]:
        challenge_obj = body.get("challenge")
        if not isinstance(challenge_obj, dict):
            raise HTTPException(status_code=400, detail="challenge required")
        peer = str(getattr(request.client, "host", "") or "unknown")[:128]
        transport = "tls13" if str(request.url.scheme).casefold() == "https" else "local" if peer in {"127.0.0.1", "::1"} else ""
        return runtime.authenticate_worker(
            challenge_obj,
            str(body.get("signature", "")),
            access_context={
                "source_ip": peer,
                "transport": transport,
                "via_server_relay": True,
                "peer_to_peer": False,
                "network_trust": "private" if peer not in {"unknown", ""} else "unknown",
                "risk_score": 0,
                "auth_age_seconds": 0,
            },
        )

    @app.post("/enterprise/v1/worker/heartbeat")
    def heartbeat(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        token = worker_token(authorization)
        resources = body.get("resources")
        runtime.heartbeat_worker(token, resources if isinstance(resources, dict) else None)
        return {"status": "ok"}

    @app.post("/enterprise/v1/worker/lease")
    def lease(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        token = worker_token(authorization)
        seconds = bounded_int(body.get("lease_seconds", DEFAULT_LEASE_SECONDS), "lease_seconds", minimum=15, maximum=15 * 60)
        return {"lease": _lease_dict(runtime.lease(token, lease_seconds=seconds))}

    @app.post("/enterprise/v1/worker/lease/batch")
    def lease_batch(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        token = worker_token(authorization)
        seconds = bounded_int(body.get("lease_seconds", DEFAULT_LEASE_SECONDS), "lease_seconds", minimum=15, maximum=15 * 60)
        max_items = bounded_int(body.get("max_items", 8), "max_items", minimum=1, maximum=MAX_WORKER_SLOTS)
        leases = runtime.lease_batch(token, max_items=max_items, lease_seconds=seconds)
        return {"leases": [_lease_dict(item) for item in leases]}

    @app.post("/enterprise/v1/worker/job/start")
    def start(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        runtime.start_worker_job(worker_token(authorization), str(body.get("job_id", "")), str(body.get("lease_token", "")))
        return {"status": "ok"}

    @app.post("/enterprise/v1/worker/job/renew")
    def renew(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        expires = runtime.renew_worker_lease(
            worker_token(authorization), str(body.get("job_id", "")), str(body.get("lease_token", "")),
            bounded_int(body.get("lease_seconds", DEFAULT_LEASE_SECONDS), "lease_seconds", minimum=15, maximum=15 * 60),
        )
        return {"lease_expires_at": expires}

    @app.post("/enterprise/v1/worker/job/handover")
    def handover(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        state = runtime.handover_worker_lease(
            worker_token(authorization),
            str(body.get("job_id", "")),
            str(body.get("lease_token", "")),
            str(body.get("reason", "WORKER_HANDOVER"))[:128],
        )
        return {"state": state}

    @app.post("/enterprise/v1/worker/job/checkpoint")
    def checkpoint(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        cp = body.get("checkpoint")
        if not isinstance(cp, dict):
            raise HTTPException(status_code=400, detail="checkpoint object required")
        seq = runtime.checkpoint_worker(
            worker_token(authorization), str(body.get("job_id", "")), str(body.get("lease_token", "")), cp,
        )
        return {"checkpoint_seq": seq}

    @app.post("/enterprise/v1/worker/job/side-effect-started")
    def side_effect_started(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        runtime.mark_worker_side_effect_started(worker_token(authorization), str(body.get("job_id", "")), str(body.get("lease_token", "")))
        return {"status": "ok"}

    @app.post("/enterprise/v1/worker/job/complete")
    def complete(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        result = body.get("result")
        if not isinstance(result, dict):
            raise HTTPException(status_code=400, detail="result object required")
        runtime.complete_worker_job(
            worker_token(authorization), str(body.get("job_id", "")), str(body.get("lease_token", "")), result,
        )
        return {"status": "ok"}

    @app.post("/enterprise/v1/worker/job/fail")
    def fail(body: dict[str, Any], authorization: str = Header(default="")) -> dict[str, Any]:
        state = runtime.fail_worker_job(
            worker_token(authorization), str(body.get("job_id", "")), str(body.get("lease_token", "")),
            str(body.get("error_code", "WORKER_JOB_FAILED")), bool(body.get("retryable", True)),
        )
        return {"state": state}

    return app


class _WorkerClientAuthState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.identity: dict[str, Any] | None = None
        self.session_token = ""
        self.generation = 0

    def snapshot(self) -> tuple[dict[str, Any] | None, str, int]:
        with self.lock:
            identity = None if self.identity is None else dict(self.identity)
            return identity, self.session_token, self.generation

    def update_identity(self, identity: Mapping[str, Any]) -> None:
        with self.lock:
            self.identity = dict(identity)

    def update_session(self, identity: Mapping[str, Any], token: str) -> int:
        with self.lock:
            self.identity = dict(identity)
            self.session_token = str(token)
            self.generation += 1
            return self.generation

    def clear_session_if_generation(self, generation: int) -> None:
        with self.lock:
            if self.generation == int(generation):
                self.session_token = ""


class EnterpriseWorkerHTTPClient:
    





    def __init__(
        self, endpoint: str, expected_root_fingerprint: str, *, ca_file: Path | None = None,
        timeout: float = 15.0, allow_tls12: bool = False,
    ) -> None:
        parsed = urlsplit(str(endpoint))
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("Enterprise Worker endpoint must be an https URL")
        self.endpoint = str(endpoint)
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.base_path = parsed.path.rstrip("/")
        self.expected_root_fingerprint = str(expected_root_fingerprint).strip().casefold()
        if len(self.expected_root_fingerprint) != 64:
            raise ValueError("expected Enterprise Root fingerprint must be SHA-256 hex")
        self.timeout = max(1.0, min(120.0, float(timeout)))
        self.ca_file = None if ca_file is None else Path(ca_file)
        self.context = ssl.create_default_context(cafile=str(self.ca_file) if self.ca_file else None)
        self.allow_tls12 = bool(allow_tls12)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2 if self.allow_tls12 else ssl.TLSVersion.TLSv1_3
        if hasattr(ssl, "OP_NO_COMPRESSION"):
            self.context.options |= ssl.OP_NO_COMPRESSION
        self._auth_state = _WorkerClientAuthState()

    def _connection(self) -> http.client.HTTPSConnection:
        return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)

    @staticmethod
    def _decode_response(response: http.client.HTTPResponse) -> dict[str, Any]:
        raw = response.read(MAX_API_BODY_BYTES + 1)
        if len(raw) > MAX_API_BODY_BYTES:
            raise RuntimeError("Enterprise Server response exceeds safety limit")
        try:
            value = _json_object_no_duplicates(raw)
        except ValueError as exc:
            raise RuntimeError("Enterprise Server returned invalid or duplicate-key JSON") from exc
        if response.status < 200 or response.status >= 300:
            detail = value.get("detail", f"HTTP {response.status}") if isinstance(value, dict) else f"HTTP {response.status}"
            raise RuntimeError(f"Enterprise Server request failed: {detail}")
        if not isinstance(value, dict):
            raise RuntimeError("Enterprise Server response must be a JSON object")
        return value

    def fork(self) -> "EnterpriseWorkerHTTPClient":
        clone = EnterpriseWorkerHTTPClient(
            self.endpoint, self.expected_root_fingerprint, ca_file=self.ca_file,
            timeout=self.timeout, allow_tls12=self.allow_tls12,
        )
        clone._auth_state = self._auth_state
        return clone

    def _refresh_identity_on_connection(
        self, connection: http.client.HTTPSConnection, peer_der: bytes, trace: str,
    ) -> dict[str, Any]:
        trace_context = TraceContext.from_correlation(trace)
        identity_headers = {CORRELATION_HEADER: trace, **trace_context.headers()}
        connection.request("GET", self.base_path + "/enterprise/v1/identity", headers=identity_headers)
        identity = self._decode_response(connection.getresponse())
        verified = verify_enterprise_server_identity(identity, self.expected_root_fingerprint, peer_der)
        self._auth_state.update_identity(verified)
        return verified

    def _verify_cached_or_refresh_identity(
        self, connection: http.client.HTTPSConnection, peer_der: bytes, trace: str,
    ) -> dict[str, Any]:
        identity, _token, _generation = self._auth_state.snapshot()
        if identity is not None:
            try:
                return verify_enterprise_server_identity(identity, self.expected_root_fingerprint, peer_der)
            except ArenyxaError as exc:
                if exc.code not in {"SERVER_IDENTITY_EXPIRED", "SERVER_TLS_BINDING_INVALID"}:
                    raise
        return self._refresh_identity_on_connection(connection, peer_der, trace)

    def verify_peer(self, correlation_id: str | None = None) -> dict[str, Any]:
        trace = normalize_correlation_id(correlation_id)
        connection = self._connection()
        try:
            connection.connect()
            sock = connection.sock
            if sock is None:
                raise RuntimeError("TLS peer socket unavailable")
            peer_der = sock.getpeercert(binary_form=True)
            return self._refresh_identity_on_connection(connection, peer_der, trace)
        finally:
            connection.close()

    def request(
        self, path: str, body: Mapping[str, Any], *, authenticated: bool = True, correlation_id: str | None = None,
    ) -> dict[str, Any]:
        trace = normalize_correlation_id(correlation_id)
        raw = _json_bytes(dict(body))
        if len(raw) > MAX_API_BODY_BYTES:
            raise ValueError("worker request exceeds safety limit")
        trace_context = TraceContext.from_correlation(trace)
        headers = {
            "content-type": "application/json", "content-length": str(len(raw)),
            CORRELATION_HEADER: trace, **trace_context.headers(),
        }
        _identity, token, _generation = self._auth_state.snapshot()
        if authenticated:
            if not token:
                raise RuntimeError("worker session is not authenticated")
            headers["authorization"] = "Bearer " + token
        connection = self._connection()
        try:
            connection.connect()
            sock = connection.sock
            if sock is None:
                raise RuntimeError("Enterprise Server TLS peer is unavailable")
            peer_der = sock.getpeercert(binary_form=True)
            self._verify_cached_or_refresh_identity(connection, peer_der, trace)
            connection.request("POST", self.base_path + path, body=raw, headers=headers)
            return self._decode_response(connection.getresponse())
        finally:
            connection.close()

    def authenticate(self, worker_id: str, signer: Any) -> dict[str, Any]:
        trace = normalize_correlation_id("worker-auth:" + str(worker_id)[:80])
        challenge = self.request(
            "/enterprise/v1/worker/challenge", {"worker_id": worker_id}, authenticated=False, correlation_id=trace,
        )
        schema = str(challenge.get("schema", ""))
        message_payload = {
            "schema": schema,
            "challenge_id": str(challenge["challenge_id"]),
            "worker_id": str(challenge["worker_id"]),
            "nonce": str(challenge["nonce"]),
            "expires_at": float(challenge["expires_at"]),
            "protocol": int(challenge["protocol"]),
        }
        if schema == "arenyxa.enterprise-worker-challenge/v2":
            algorithm = str(challenge.get("identity_algorithm", ""))
            signer_algorithm = str(getattr(signer, "identity_algorithm", algorithm))
            if signer_algorithm and signer_algorithm != algorithm:
                raise RuntimeError("Worker signer algorithm does not match the registered hardware identity profile")
            message_payload["identity_algorithm"] = algorithm
        elif schema != "arenyxa.enterprise-worker-challenge/v1":
            raise RuntimeError("Enterprise Server returned an unsupported Worker challenge schema")
        message = _json_bytes(message_payload)
        sign_method = getattr(signer, "sign", None)
        signature = bytes(sign_method(message) if callable(sign_method) else signer(message))
        proof = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        session = self.request(
            "/enterprise/v1/worker/auth", {"challenge": challenge, "signature": proof}, authenticated=False, correlation_id=trace,
        )
        identity, _old_token, _generation = self._auth_state.snapshot()
        if identity is None:
            identity = self.verify_peer(trace)
        self._auth_state.update_session(identity, str(session["session_token"]))
        return session
