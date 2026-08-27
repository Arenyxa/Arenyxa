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
from arenyxa.enterprise.transport_security import BoundedWindowRateLimiter, normalize_correlation_id
from arenyxa.enterprise.distributed import (
    CURRENT_PROTOCOL,
    DEFAULT_LEASE_SECONDS,
    MAX_CHECKPOINT_BYTES,
    MAX_JOB_PAYLOAD_BYTES,
    MAX_RESULT_BYTES,
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
    def hook(pairs):
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


def create_enterprise_server_app(runtime: EnterpriseServerRuntime, server_identity: Any) -> Any:
    





    try:
        from fastapi import FastAPI, Header, HTTPException, Request
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise RuntimeError("Enterprise Server mode requires: pip install -e .[server]") from exc

    def current_identity() -> dict[str, Any]:
        value = server_identity() if callable(server_identity) else server_identity
        if not isinstance(value, Mapping):
            raise RuntimeError("Enterprise Server identity provider returned an invalid artifact")
        return dict(value)

    app = FastAPI(title="Arenyxa Enterprise Worker Service", version=str(CURRENT_PROTOCOL))
    peer_limiter = BoundedWindowRateLimiter(MAX_SERVER_RATE_BUCKETS)
    auth_limiter = BoundedWindowRateLimiter(MAX_SERVER_RATE_BUCKETS)
    inflight_slots = threading.BoundedSemaphore(MAX_SERVER_INFLIGHT_REQUESTS)

    @app.middleware("http")
    async def transport_guard(request: Request, call_next):
        correlation_id = normalize_correlation_id(request.headers.get(CORRELATION_HEADER))
        request.state.correlation_id = correlation_id
        peer = str(getattr(request.client, "host", "") or "unknown")[:128]

        def finalize(response):
            response.headers[CORRELATION_HEADER] = correlation_id
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response

        if not peer_limiter.allow(peer, limit=MAX_SERVER_REQUESTS_PER_MINUTE):
            return finalize(JSONResponse(status_code=429, content={"detail": "request rate limit exceeded"}))
        if request.url.path in {"/enterprise/v1/worker/challenge", "/enterprise/v1/worker/auth"}:
            if not auth_limiter.allow(peer, limit=MAX_SERVER_AUTH_REQUESTS_PER_MINUTE):
                return finalize(JSONResponse(status_code=429, content={"detail": "authentication rate limit exceeded"}))
        if not inflight_slots.acquire(blocking=False):
            return finalize(JSONResponse(status_code=503, content={"detail": "server request capacity exhausted"}))
        status = 500
        try:
                                                                                                 
                                                                                                    
                                                                                    
            if request.method.upper() in {"POST", "PUT", "PATCH"}:
                if request.headers.get("transfer-encoding"):
                    response = JSONResponse(status_code=400, content={"detail": "transfer-encoding is not supported"})
                    status = response.status_code
                    return finalize(response)
                raw_length = request.headers.get("content-length", "")
                if not raw_length:
                    response = JSONResponse(status_code=411, content={"detail": "content-length required"})
                    status = response.status_code
                    return finalize(response)
                try:
                    length = int(raw_length)
                except ValueError:
                    response = JSONResponse(status_code=400, content={"detail": "invalid content-length"})
                    status = response.status_code
                    return finalize(response)
                if length < 0:
                    response = JSONResponse(status_code=400, content={"detail": "invalid content-length"})
                    status = response.status_code
                    return finalize(response)
                if length > MAX_API_BODY_BYTES:
                    response = JSONResponse(status_code=413, content={"detail": "request body too large"})
                    status = response.status_code
                    return finalize(response)
                raw = await request.body()
                if len(raw) != length:
                    response = JSONResponse(status_code=400, content={"detail": "content-length mismatch"})
                    status = response.status_code
                    return finalize(response)
                if len(raw) > MAX_API_BODY_BYTES:
                    response = JSONResponse(status_code=413, content={"detail": "request body too large"})
                    status = response.status_code
                    return finalize(response)
                if raw:
                    try:
                        _json_object_no_duplicates(raw)
                    except ValueError:
                        response = JSONResponse(status_code=400, content={"detail": "invalid or duplicate-key JSON"})
                        status = response.status_code
                        return finalize(response)
            response = await call_next(request)
            status = int(getattr(response, "status_code", 500))
            return finalize(response)
        finally:
            inflight_slots.release()
            LOGGER.info(
                "enterprise worker protocol request",
                extra={
                    "correlation_id": correlation_id,
                    "phase": "enterprise-server-http",
                    "resource_id": request.url.path[:256],
                    "error_code": "" if status < 400 else f"HTTP_{status}",
                },
            )

    @app.exception_handler(ArenyxaError)
    async def enterprise_error(_request: Request, exc: ArenyxaError):
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

    def worker_token(authorization: str) -> str:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="worker authentication required")
        token = authorization[7:].strip()
        if not token:
            raise HTTPException(status_code=401, detail="worker authentication required")
        return token

    def bounded_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid {label}") from exc
        if parsed < minimum or parsed > maximum:
            raise HTTPException(status_code=400, detail=f"{label} outside supported range")
        return parsed

    @app.get("/enterprise/v1/identity")
    def get_identity() -> dict[str, Any]:
        return current_identity()

    @app.get("/enterprise/v1/health")
    def health() -> dict[str, Any]:
        payload = dict(runtime.queue.health())
        payload["transport_security"] = {
            "peer_rate_buckets": peer_limiter.bucket_count(),
            "auth_rate_buckets": auth_limiter.bucket_count(),
            "max_requests_per_minute": MAX_SERVER_REQUESTS_PER_MINUTE,
            "max_auth_requests_per_minute": MAX_SERVER_AUTH_REQUESTS_PER_MINUTE,
            "max_inflight_requests": MAX_SERVER_INFLIGHT_REQUESTS,
            "correlation_header": CORRELATION_HEADER,
        }
        return payload

    @app.post("/enterprise/v1/worker/challenge")
    def challenge(body: dict[str, Any]) -> dict[str, Any]:
        return runtime.create_worker_challenge(str(body.get("worker_id", "")))

    @app.post("/enterprise/v1/worker/auth")
    def authenticate(body: dict[str, Any]) -> dict[str, Any]:
        challenge_obj = body.get("challenge")
        if not isinstance(challenge_obj, dict):
            raise HTTPException(status_code=400, detail="challenge required")
        return runtime.authenticate_worker(challenge_obj, str(body.get("signature", "")))

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


class EnterpriseWorkerHTTPClient:
    





    def __init__(self, endpoint: str, expected_root_fingerprint: str, *, ca_file: Path | None = None, timeout: float = 15.0) -> None:
        parsed = urlsplit(str(endpoint))
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("Enterprise Worker endpoint must be an https URL")
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.base_path = parsed.path.rstrip("/")
        self.expected_root_fingerprint = str(expected_root_fingerprint).strip().casefold()
        if len(self.expected_root_fingerprint) != 64:
            raise ValueError("expected Enterprise Root fingerprint must be SHA-256 hex")
        self.timeout = max(1.0, min(120.0, float(timeout)))
        self.context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        if hasattr(ssl, "OP_NO_COMPRESSION"):
            self.context.options |= ssl.OP_NO_COMPRESSION
        self._identity: dict[str, Any] | None = None
        self._session_token = ""

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

    def verify_peer(self, correlation_id: str | None = None) -> dict[str, Any]:
        trace = normalize_correlation_id(correlation_id)
        connection = self._connection()
        try:
            connection.request("GET", self.base_path + "/enterprise/v1/identity", headers={CORRELATION_HEADER: trace})
            response = connection.getresponse()
                                                                                            
            sock = connection.sock
            if sock is None:
                raise RuntimeError("TLS peer socket unavailable")
            peer_der = sock.getpeercert(binary_form=True)
            identity = self._decode_response(response)
            verify_enterprise_server_identity(identity, self.expected_root_fingerprint, peer_der)
            self._identity = identity
            return identity
        finally:
            connection.close()

    def request(
        self, path: str, body: Mapping[str, Any], *, authenticated: bool = True, correlation_id: str | None = None,
    ) -> dict[str, Any]:
        trace = normalize_correlation_id(correlation_id)
        if self._identity is None:
            self.verify_peer(trace)
        raw = _json_bytes(dict(body))
        if len(raw) > MAX_API_BODY_BYTES:
            raise ValueError("worker request exceeds safety limit")
        headers = {"content-type": "application/json", "content-length": str(len(raw)), CORRELATION_HEADER: trace}
        if authenticated:
            if not self._session_token:
                raise RuntimeError("worker session is not authenticated")
            headers["authorization"] = "Bearer " + self._session_token
        connection = self._connection()
        try:
                                                                                                  
                                                                                                    
                                                                                                  
                                                 
            connection.connect()
            sock = connection.sock
            if sock is None:
                raise RuntimeError("Enterprise Server TLS peer is unavailable")
            peer_der = sock.getpeercert(binary_form=True)
            connection.request("GET", self.base_path + "/enterprise/v1/identity", headers={CORRELATION_HEADER: trace})
            identity_response = connection.getresponse()
            refreshed_identity = self._decode_response(identity_response)
            verify_enterprise_server_identity(refreshed_identity, self.expected_root_fingerprint, peer_der)
            self._identity = refreshed_identity
            connection.request("POST", self.base_path + path, body=raw, headers=headers)
            return self._decode_response(connection.getresponse())
        finally:
            connection.close()

    def authenticate(self, worker_id: str, signer: Any) -> dict[str, Any]:
        trace = normalize_correlation_id("worker-auth:" + str(worker_id)[:80])
        challenge = self.request(
            "/enterprise/v1/worker/challenge", {"worker_id": worker_id}, authenticated=False, correlation_id=trace,
        )
        message = _json_bytes({
            "schema": "arenyxa.enterprise-worker-challenge/v1",
            "challenge_id": str(challenge["challenge_id"]),
            "worker_id": str(challenge["worker_id"]),
            "nonce": str(challenge["nonce"]),
            "expires_at": float(challenge["expires_at"]),
            "protocol": int(challenge["protocol"]),
        })
        signature = bytes(signer(message))
        proof = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        session = self.request(
            "/enterprise/v1/worker/auth", {"challenge": challenge, "signature": proof}, authenticated=False, correlation_id=trace,
        )
        self._session_token = str(session["session_token"])
        return session
