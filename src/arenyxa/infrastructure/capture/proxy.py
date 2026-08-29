from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import fnmatch
import json
import logging
import os
import socket
import ssl
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from arenyxa.domain.models import utc_now
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard
from arenyxa.security.dlp import GLOBAL_DLP_ENGINE

from arenyxa.infrastructure.capture.proxy_transport import (
    _ProxyTCPServer,
    _ProxyTCPServerV6,
    _ProxyRequestHandler,
    _secure_write,
    _read_head,
    _parse_head,
    _header,
    _expects_continue,
    _read_message_body,
    _assemble_message,
    _connect_validated_candidates,
    _parse_raw_message,
    _split_host_port,
    _format_authority,
    _request_destination,
    _normalize_forward_request,
    _read_response,
    _relay,
    _error_response,
    _send_error,
)

from arenyxa.infrastructure.capture.proxy_models import (
    ProxySettings,
    ProxyFlow,
    summarize_proxy_flows,
    inspect_proxy_flow,
    PendingIntercept,
    ProxyAutoResponderRule,
    ProxyMatchReplaceRule,
    ProxyStatus,
    LocalCertificateAuthority,
    ProxyArchive,
)
from arenyxa.infrastructure.capture.proxy_rules import InterceptAction, InterceptRuleEngine
from arenyxa.infrastructure.capture.proxy_store import ProxyHistoryStore
from arenyxa.infrastructure.capture.proxy_export import export_proxy_har
from arenyxa.infrastructure.capture.proxy_resilience import ProxyResilienceMixin


LOGGER = logging.getLogger(__name__)
class InterceptingProxy(ProxyResilienceMixin):
    """Run the bounded local interception proxy, persistence, DLP, and TLS inspection pipeline."""
    def __init__(self, root: Path, settings: ProxySettings | None = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.settings = settings or ProxySettings()
        self.settings.validate()
        self.ca = LocalCertificateAuthority(self.root / "ca")
        self.history_store = ProxyHistoryStore(
            self.root / "proxy-history.sqlite3",
            body_limit=self.settings.max_message_bytes,
        )
        self.archive = ProxyArchive(self.root / "archive")
        self._persistence_lifecycle_lock = threading.RLock()
        self.persistence = self._new_persistence_pipeline(self.settings.persistence_queue_capacity)
        self.rule_engine = InterceptRuleEngine(self.root / "intercept-rules.json")
        self.network_guard = self._build_network_guard(self.settings)
        self._lock = threading.RLock()
        self._client_condition = threading.Condition(self._lock)
        self._active_clients: set[socket.socket] = set()
        self._closed = False
        recovered_sessions = self.history_store.recover_interrupted()
        if recovered_sessions:
            LOGGER.warning("Recovered %d interrupted Proxy Suite session(s)", recovered_sessions)
        self._history: list[ProxyFlow] = self.history_store.recent(min(self.settings.history_limit, 1000))
        self._pending: dict[str, PendingIntercept] = {}
        self._sequence = max((item.sequence for item in self._history), default=0)
        self._server: _ProxyTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._started_at = ""
        self._session_id = ""
        self._listeners: list[Callable[[str, Any], None]] = []
        self._performance_telemetry: Any = None
        self._rules_path = self.root / "autoresponder-rules.json"
        self._autoresponder_rules: list[ProxyAutoResponderRule] = []
        self._rewrite_rules_path = self.root / "match-replace-rules.json"
        self._match_replace_rules: list[ProxyMatchReplaceRule] = []
        self._load_autoresponder_rules()
        self._load_match_replace_rules()
    @staticmethod
    def _dlp_decision(
        scheme: str, host: str, port: int, target: str,
        headers: list[tuple[str, str]], body: bytes,
    ):
        header_map = {str(name): str(value) for name, value in headers}
        default_port = 443 if str(scheme).casefold() == "https" else 80
        authority = _format_authority(host, port, default_port)
        url = f"{scheme}://{authority}{target if str(target).startswith('/') else '/' + str(target)}"
        return GLOBAL_DLP_ENGINE.inspect_http(url=url, headers=header_map, body=body)

    @staticmethod
    def _build_network_guard(settings: ProxySettings) -> NetworkUseGuard:
        return NetworkUseGuard(NetworkGuardPolicy(
            enabled=settings.network_guard_enabled,
            max_concurrent_connections=settings.max_concurrent_upstreams,
            max_global_connects_per_minute=settings.max_upstream_connects_per_minute,
            max_target_connects_per_minute=settings.max_target_connects_per_minute,
            max_distinct_targets_per_minute=settings.max_distinct_targets_per_minute,
            max_tracked_targets=settings.max_tracked_targets,
            block_cloud_metadata=settings.block_cloud_metadata,
            block_private_or_loopback=bool(settings.allow_remote_clients and settings.block_private_targets_when_remote),
        ))
    def apply_settings(self, settings: ProxySettings) -> None:
        """Validate and atomically apply proxy runtime settings while stopped."""
        settings.validate()
        replacement_guard = self._build_network_guard(settings)
        with self._persistence_lifecycle_lock:
            with self._lock:
                if self._closed:
                    raise RuntimeError("Proxy engine is closed")
                if self.running or self._active_clients:
                    raise RuntimeError("Proxy settings cannot be replaced while the listener is active")
                old_capacity = self.settings.persistence_queue_capacity
            self._reconfigure_persistence(old_capacity, settings)
            with self._lock:
                self.settings = settings
                self.network_guard = replacement_guard
    def _load_autoresponder_rules(self) -> None:
        try:
            if not self._rules_path.is_file():
                return
            value = json.loads(self._rules_path.read_text(encoding="utf-8"))
            if not isinstance(value, list) or len(value) > 256:
                raise ValueError("AutoResponder rules file is invalid")
            loaded: list[ProxyAutoResponderRule] = []
            for item in value:
                if not isinstance(item, dict):
                    raise ValueError("AutoResponder rule entry is invalid")
                rule = ProxyAutoResponderRule(
                    id=str(item.get("id", "")), enabled=bool(item.get("enabled", True)),
                    host_pattern=str(item.get("host_pattern", "")), path_pattern=str(item.get("path_pattern", "/*")),
                    method=str(item.get("method", "*")).upper(), status=int(item.get("status", 200)),
                    reason=str(item.get("reason", "Arenyxa AutoResponder")),
                    content_type=str(item.get("content_type", "text/plain; charset=utf-8")), body=str(item.get("body", "")),
                )
                rule.validate()
                loaded.append(rule)
            self._autoresponder_rules = loaded
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
            self._autoresponder_rules = []
    def _save_autoresponder_rules(self) -> None:
        payload = json.dumps([rule.snapshot() for rule in self._autoresponder_rules], ensure_ascii=False, indent=2).encode("utf-8")
        temp = self._rules_path.with_name(self._rules_path.name + f".{uuid.uuid4().hex}.tmp")
        _secure_write(temp, payload, public=False)
        try:
            os.replace(temp, self._rules_path)
            try:
                os.chmod(self._rules_path, 0o600)
            except OSError:
                record_current_exception(__name__, 'InterceptingProxy._save_autoresponder_rules:169')
        finally:
            if temp.exists():
                try:
                    temp.unlink()
                except OSError:
                    record_current_exception(__name__, 'InterceptingProxy._save_autoresponder_rules:175')
    def autoresponder_rules(self) -> list[dict[str, Any]]:
        """Return the configured bounded auto-responder rules."""
        with self._lock:
            return [rule.snapshot() for rule in self._autoresponder_rules]
    def add_autoresponder_rule(
        self, host_pattern: str, path_pattern: str, *, method: str = "*", status: int = 200,
        reason: str = "Arenyxa AutoResponder", content_type: str = "application/json; charset=utf-8",
        body: str = "{}", enabled: bool = True,
    ) -> dict[str, Any]:
        """Add one validated auto-responder rule."""
        rule = ProxyAutoResponderRule(
            id=uuid.uuid4().hex, enabled=bool(enabled), host_pattern=str(host_pattern).strip(),
            path_pattern=str(path_pattern).strip() or "/*", method=str(method).strip().upper() or "*",
            status=int(status), reason=str(reason), content_type=str(content_type), body=str(body),
        )
        rule.validate()
        with self._lock:
            if len(self._autoresponder_rules) >= 256:
                raise ValueError("AutoResponder reached the 256-rule safety limit")
            self._autoresponder_rules.append(rule)
            self._save_autoresponder_rules()
        return rule.snapshot()
    def remove_autoresponder_rule(self, rule_id: str) -> bool:
        """Remove one auto-responder rule by identifier."""
        with self._lock:
            before = len(self._autoresponder_rules)
            self._autoresponder_rules = [rule for rule in self._autoresponder_rules if rule.id != str(rule_id)]
            changed = len(self._autoresponder_rules) != before
            if changed:
                self._save_autoresponder_rules()
            return changed
    def _autoresponder_response(self, method: str, host: str, target: str) -> tuple[ProxyAutoResponderRule, bytes] | None:
        with self._lock:
            rules = list(self._autoresponder_rules)
        for rule in rules:
            if rule.matches(method, host, target):
                response = rule.response()
                if len(response) > self.settings.max_message_bytes:
                    raise ValueError("AutoResponder response exceeds the configured proxy message budget")
                return rule, response
        return None
    def _load_match_replace_rules(self) -> None:
        try:
            if not self._rewrite_rules_path.is_file():
                return
            value = json.loads(self._rewrite_rules_path.read_text(encoding="utf-8"))
            if not isinstance(value, list) or len(value) > 256:
                raise ValueError("Match/Replace rules file is invalid")
            loaded: list[ProxyMatchReplaceRule] = []
            for item in value:
                if not isinstance(item, dict):
                    raise ValueError("Match/Replace rule entry is invalid")
                rule = ProxyMatchReplaceRule(
                    id=str(item.get("id", "")), enabled=bool(item.get("enabled", True)),
                    phase=str(item.get("phase", "request")).casefold(),
                    scope=str(item.get("scope", "header")).casefold(),
                    host_pattern=str(item.get("host_pattern", "*")), path_pattern=str(item.get("path_pattern", "/*")),
                    method=str(item.get("method", "*")).upper(), header_name=str(item.get("header_name", "*")),
                    match=str(item.get("match", "")), replacement=str(item.get("replacement", "")),
                )
                rule.validate()
                loaded.append(rule)
            self._match_replace_rules = loaded
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
            self._match_replace_rules = []
    def _save_match_replace_rules(self) -> None:
        payload = json.dumps([rule.snapshot() for rule in self._match_replace_rules], ensure_ascii=False, indent=2).encode("utf-8")
        temp = self._rewrite_rules_path.with_name(self._rewrite_rules_path.name + f".{uuid.uuid4().hex}.tmp")
        _secure_write(temp, payload, public=False)
        try:
            os.replace(temp, self._rewrite_rules_path)
            try:
                os.chmod(self._rewrite_rules_path, 0o600)
            except OSError:
                record_current_exception(__name__, 'InterceptingProxy._save_match_replace_rules:256')
        finally:
            if temp.exists():
                try:
                    temp.unlink()
                except OSError:
                    record_current_exception(__name__, 'InterceptingProxy._save_match_replace_rules:262')
    def match_replace_rules(self) -> list[dict[str, Any]]:
        """Return the configured request and response match-replace rules."""
        with self._lock:
            return [rule.snapshot() for rule in self._match_replace_rules]

    def intercept_rules(self) -> list[dict[str, Any]]:
        """Return ordered professional InterceptRule definitions."""
        return self.rule_engine.list()

    def add_intercept_rule(
        self,
        name: str,
        action: str,
        *,
        phase: str = "both",
        priority: int = 100,
        host_pattern: str = "*",
        url_pattern: str = "*",
        method_pattern: str = "*",
        header_pattern: str = "*",
        body_pattern: str = "*",
        replacement: str = "",
    ) -> dict[str, Any]:
        """Create one bounded InterceptRule without replacing legacy rewrite rules."""
        return self.rule_engine.add(
            name,
            action,
            phase=phase,
            priority=priority,
            host_pattern=host_pattern,
            url_pattern=url_pattern,
            method_pattern=method_pattern,
            header_pattern=header_pattern,
            body_pattern=body_pattern,
            replacement=replacement,
        )

    def remove_intercept_rule(self, rule_id: str) -> bool:
        """Remove a professional InterceptRule by id."""
        return self.rule_engine.remove(rule_id)

    def add_match_replace_rule(
        self, phase: str, scope: str, match: str, replacement: str, *, host_pattern: str = "*",
        path_pattern: str = "/*", method: str = "*", header_name: str = "*", enabled: bool = True,
    ) -> dict[str, Any]:
        """Add one validated match-replace rule."""
        rule = ProxyMatchReplaceRule(
            id=uuid.uuid4().hex, enabled=bool(enabled), phase=str(phase).casefold(), scope=str(scope).casefold(),
            host_pattern=str(host_pattern).strip() or "*", path_pattern=str(path_pattern).strip() or "/*",
            method=str(method).strip().upper() or "*", header_name=str(header_name).strip() or "*",
            match=str(match), replacement=str(replacement),
        )
        rule.validate()
        with self._lock:
            if len(self._match_replace_rules) >= 256:
                raise ValueError("Match/Replace reached the 256-rule safety limit")
            self._match_replace_rules.append(rule)
            self._save_match_replace_rules()
        return rule.snapshot()

    def remove_match_replace_rule(self, rule_id: str) -> bool:
        """Remove one match-replace rule by identifier."""
        with self._lock:
            before = len(self._match_replace_rules)
            self._match_replace_rules = [rule for rule in self._match_replace_rules if rule.id != str(rule_id)]
            changed = len(self._match_replace_rules) != before
            if changed:
                self._save_match_replace_rules()
            return changed

    def _apply_match_replace(
        self, raw: bytes, phase: str, method: str, host: str, target: str,
    ) -> tuple[bytes, list[str]]:
        with self._lock:
            rules = [rule for rule in self._match_replace_rules if rule.matches_message(phase, method, host, target)]
        if not rules:
            return raw, []
        start_line, headers, body = _parse_raw_message(raw)
        applied: list[str] = []
        transfer_chunked = "chunked" in _header(headers, "Transfer-Encoding").casefold()
        for rule in rules:
            changed = False
            if rule.scope == "header":
                rewritten: list[tuple[str, str]] = []
                for name, value in headers:
                    if rule.header_name == "*" or fnmatch.fnmatchcase(name.casefold(), rule.header_name.casefold()):
                        updated = value.replace(rule.match, rule.replacement)
                        changed = changed or updated != value
                        value = updated
                    rewritten.append((name, value))
                headers = rewritten
            elif not transfer_chunked:
                needle = rule.match.encode("utf-8")
                replacement = rule.replacement.encode("utf-8")
                updated_body = body.replace(needle, replacement)
                changed = updated_body != body
                body = updated_body
            if changed:
                applied.append(rule.id)
        if not applied:
            return raw, []
        if len(body) > self.settings.max_message_bytes:
            raise ValueError("Match/Replace result exceeds the configured proxy message budget")
        if not transfer_chunked:
            normalized_headers: list[tuple[str, str]] = []
            saw_length = False
            for name, value in headers:
                if name.casefold() == "content-length":
                    if saw_length:
                        continue
                    saw_length = True
                    normalized_headers.append(("Content-Length", str(len(body))))
                else:
                    normalized_headers.append((name, value))
            if body and not saw_length:
                normalized_headers.append(("Content-Length", str(len(body))))
            headers = normalized_headers
        result = _assemble_message(start_line, headers, body)
        if len(result) > self.settings.max_message_bytes:
            raise ValueError("Match/Replace result exceeds the configured proxy message budget")
        return result, applied

    def add_listener(self, callback: Callable[[str, Any], None]) -> None:
        """Register one bounded local proxy listener."""
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[str, Any], None]) -> None:
        """Remove one configured proxy listener."""
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def _emit(self, kind: str, value: Any) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for callback in listeners:
            try:
                callback(kind, value)
            except Exception:
                continue

    @property
    def running(self) -> bool:
        """Return whether the primary proxy listener is active."""
        return self._server is not None

    @property
    def address(self) -> tuple[str, int]:
        """Return the primary listener address when active."""
        server = self._server
        if server is None:
            return self.settings.bind_host, int(self.settings.bind_port)
        host, port = server.server_address[:2]
        return str(host), int(port)

    def status(self) -> ProxyStatus:
        """Return proxy lifecycle and listener status metadata."""
        host, port = self.address
        with self._lock:
            flows = len(self._history)
            pending = len(self._pending)
        return ProxyStatus(self.running, host, port, flows, pending, self._started_at, bool(self.settings.tls_interception))

    def update_policy(self, intercept_requests: bool, intercept_responses: bool) -> None:
        """Replace network-use guard policy for subsequent outbound connections."""
        with self._lock:
            self.settings.intercept_requests = bool(intercept_requests)
            self.settings.intercept_responses = bool(intercept_responses)
        self._emit("policy", {"intercept_requests": bool(intercept_requests), "intercept_responses": bool(intercept_responses)})

    def start(self) -> tuple[str, int]:
        """Start configured proxy listeners after validation and local policy checks."""
        with self._persistence_lifecycle_lock:
            state = self.persistence.status()
            if state["state"] != "open" or not state["writer_alive"]:
                self._reconfigure_persistence(
                    self.settings.persistence_queue_capacity,
                    self.settings,
                )
            with self._lock:
                if self._closed:
                    raise RuntimeError("Proxy engine is closed")
                if self._server is not None:
                    return self.address
                self.settings.validate()
                server_type = _ProxyTCPServerV6 if ":" in self.settings.bind_host else _ProxyTCPServer
                server = server_type((self.settings.bind_host, int(self.settings.bind_port)), _ProxyRequestHandler)
                server.engine = self
                thread = threading.Thread(target=server.serve_forever, name="arenyxa-proxy-listener", daemon=True)
                self._server = server
                self._thread = thread
                self._started_at = utc_now()
                self._session_id = "proxy_" + uuid.uuid4().hex
                host, port = server.server_address[:2]
                self.history_store.start_session(
                    self._session_id,
                    str(host),
                    int(port),
                    started_at=self._started_at,
                )
                thread.start()
        self._emit("started", self.status())
        return self.address

    def stop(self) -> None:
        """Stop listeners and release proxy runtime resources."""
        with self._lock:
            server = self._server
            thread = self._thread
            self._server = None
            self._thread = None
            session_id = self._session_id
            self._session_id = ""
            pending = list(self._pending.values())
            self._pending.clear()
        for item in pending:
            item.action = "forward"
            item.modified_raw = item.raw
            item.event.set()
        if server is not None:
            server.shutdown()
            server.server_close()
        with self._client_condition:
            clients = list(self._active_clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                record_current_exception(__name__, 'InterceptingProxy.stop:487')
            try:
                client.close()
            except OSError:
                record_current_exception(__name__, 'InterceptingProxy.stop:491')
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=3.0)
        deadline = time.monotonic() + 3.0
        with self._client_condition:
            while self._active_clients:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._client_condition.wait(timeout=remaining)
        if session_id:
            if not self.flush_persistence():
                self._emit(
                    "error",
                    {
                        "code": "PROXY_PERSISTENCE_DRAIN_TIMEOUT",
                        "session_id": session_id,
                        "message": "Proxy persistence queue did not drain before session finalization",
                    },
                )
            try:
                self.history_store.finish_session(session_id)
            except ArenyxaError:
                LOGGER.exception("Proxy Suite session finalization failed")
                self._emit("error", {"code": "PROXY_SESSION_FINALIZE_FAILED", "session_id": session_id})
        self._emit("stopped", self.status())

    def close(self) -> None:
        """Permanently stop the proxy and close its durable history database."""
        with self._lock:
            if self._closed:
                return
        self.stop()
        with self._client_condition:
            if self._active_clients:
                LOGGER.warning(
                    "Proxy history database remains open because %d client handler(s) did not quiesce",
                    len(self._active_clients),
                )
                return
        with self._persistence_lifecycle_lock:
            with self._lock:
                if self._closed:
                    return
            if not self.persistence.close(float(self.settings.persistence_flush_timeout_seconds)):
                LOGGER.warning("Proxy persistence writer did not quiesce before close")
                return
            self.history_store.close()
            with self._lock:
                self._closed = True

    def _client_started(self, client: socket.socket) -> None:
        with self._client_condition:
            self._active_clients.add(client)

    def _client_finished(self, client: socket.socket) -> None:
        with self._client_condition:
            self._active_clients.discard(client)
            self._client_condition.notify_all()

    def history(self) -> list[ProxyFlow]:
        """Return bounded persisted proxy flow history."""
        with self._lock:
            return list(self._history)

    def history_page(
        self, *, page: int = 1, page_size: int = 100, query: str = "", session_id: str = ""
    ) -> dict[str, Any]:
        """Return one durable SQLite-backed history page."""
        self.flush_persistence(timeout=min(1.0, float(self.settings.persistence_flush_timeout_seconds)))
        return self.history_store.page(page=page, page_size=page_size, query=query, session_id=session_id)

    def sessions(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Return durable Proxy Suite capture sessions."""
        self.flush_persistence(timeout=min(1.0, float(self.settings.persistence_flush_timeout_seconds)))
        return self.history_store.sessions(limit=limit)

    def get_flow(self, flow_id: str) -> ProxyFlow | None:
        """Resolve a flow from the live window or durable history."""
        with self._lock:
            live = next((item for item in self._history if item.id == str(flow_id)), None)
        return live if live is not None else self.history_store.get(flow_id)

    def history_health(self) -> dict[str, Any]:
        """Return durable history integrity and WAL status."""
        self.flush_persistence(timeout=min(1.0, float(self.settings.persistence_flush_timeout_seconds)))
        result = self.history_store.health_check()
        result["persistence"] = self.persistence.status()
        return result

    def cleanup_history(self, *, max_records: int = 1_000_000, batch_size: int = 5_000) -> int:
        """Apply bounded automatic retention without blocking the UI for an unbounded delete."""
        self.flush_persistence(timeout=float(self.settings.persistence_flush_timeout_seconds))
        return self.history_store.cleanup(max_records=max_records, batch_size=batch_size)

    def session_summary(self, *, limit: int = 2000) -> dict[str, Any]:
        """Summarize one proxy capture session."""
        bounded = max(1, min(int(limit), 10_000))
        with self._lock:
            flows = list(self._history)[-bounded:]
        return summarize_proxy_flows(flows).snapshot()

    def pending(self) -> list[dict[str, Any]]:
        """Return pending operator interception decisions."""
        with self._lock:
            return [item.snapshot() for item in self._pending.values()]

    def inspect_flow(self, flow_id: str) -> dict[str, Any]:
        """Return structured protocol and security inspection for one proxy flow."""
        with self._lock:
            flow = next((item for item in self._history if item.id == str(flow_id)), None)
        if flow is None:
            flow = self.history_store.get(flow_id)
        if flow is None:
            raise KeyError("Proxy flow was not found")
        return inspect_proxy_flow(flow).snapshot()

    def export_har(
        self, destination: Path, *, flow_ids: set[str] | None = None, redact_sensitive: bool = True,
    ) -> Path:
        """Export bounded proxy history as a HAR-compatible artifact."""
        with self._lock:
            flows = [item for item in self._history if flow_ids is None or item.id in flow_ids]
        return export_proxy_har(destination, flows, redact_sensitive=redact_sensitive)

    def resolve(self, intercept_id: str, action: str, raw: bytes | str | None = None) -> bool:
        """Resolve a pending intercepted flow using an explicit operator action."""
        normalized = str(action).strip().casefold()
        if normalized not in {"forward", "drop"}:
            raise ValueError("Intercept action must be forward or drop")
        with self._lock:
            item = self._pending.get(str(intercept_id))
            if item is None:
                return False
            item.action = normalized
            if raw is None:
                item.modified_raw = item.raw
            elif isinstance(raw, bytes):
                item.modified_raw = raw
            else:
                item.modified_raw = str(raw).encode("latin-1", "replace")
            item.event.set()
        return True

    def export_ca_certificate(self, destination: Path) -> Path:
        """Export the local interception CA certificate to an operator-selected path."""
        return self.ca.export_certificate(destination)

    def repeat_raw(self, scheme: str, host: str, port: int, raw_request: bytes | str) -> bytes:
        """Send one explicitly requested raw HTTP message through the guarded replay path."""
        normalized_scheme = str(scheme).strip().casefold()
        if normalized_scheme not in {"http", "https"}:
            raise ValueError("Repeater scheme must be http or https")
        target_host = str(host).strip().rstrip(".")
        if not target_host:
            raise ValueError("Repeater host is required")
        target_port = int(port)
        if target_port < 1 or target_port > 65535:
            raise ValueError("Repeater port must be between 1 and 65535")
        payload = raw_request if isinstance(raw_request, bytes) else str(raw_request).encode("latin-1", "replace")
        if not payload or len(payload) > self.settings.max_message_bytes:
            raise ValueError("Repeater request is empty or exceeds the configured message budget")
        start_line, headers, body = _parse_raw_message(payload)
        parts = start_line.split(" ", 2)
        if len(parts) != 3:
            raise ValueError("Repeater request line is invalid")
        method, request_target, version = parts
        origin_target = request_target if request_target.startswith("/") else (urlsplit(request_target).path or "/")
        if urlsplit(request_target).query:
            origin_target += "?" + urlsplit(request_target).query
        normalized = _normalize_forward_request(method, origin_target, version, headers, body, target_host, target_port, normalized_scheme)
        dlp = self._dlp_decision(normalized_scheme, target_host, target_port, origin_target, headers, body)
        if not dlp.allowed:
            raise ArenyxaError(
                "DLP_EGRESS_BLOCKED", "Proxy Repeater request was blocked by DLP policy.",
                domain="SECURITY",
                context={"host": dlp.destination_host, "finding_kinds": sorted({item.kind for item in dlp.findings})},
            )
        return self._forward_upstream(normalized_scheme, target_host, target_port, method, normalized)

    def _forward_upstream(self, scheme: str, host: str, port: int, method: str, request: bytes) -> bytes:
        """Execute one guarded upstream HTTP exchange for the full socket lifetime."""
        with self.network_guard.connection_candidates(host) as connect_hosts:
            upstream = _connect_validated_candidates(connect_hosts, port, float(self.settings.connect_timeout_seconds))
            try:
                upstream.settimeout(float(self.settings.read_timeout_seconds))
                if scheme == "https":
                    context = ssl.create_default_context()
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.set_alpn_protocols(["http/1.1"])
                    if not self.settings.verify_upstream_tls:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    upstream = context.wrap_socket(upstream, server_hostname=host)
                upstream.sendall(request)
                return _read_response(upstream, method.upper(), self.settings.max_header_bytes, self.settings.max_message_bytes)
            finally:
                try:
                    upstream.close()
                except OSError:
                    record_current_exception(__name__, 'InterceptingProxy._forward_upstream:686')

    def _new_flow(self, client: str, scheme: str, method: str, host: str, port: int, target: str) -> ProxyFlow:
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
        return ProxyFlow(uuid.uuid4().hex, sequence, utc_now(), client, scheme, method, host, int(port), target)

    def _complete(self, flow: ProxyFlow, started: float) -> None:
        flow.duration_ms = max(0.0, (time.monotonic() - started) * 1000.0)
        flow.completed_at = utc_now()
        self._record_completed_proxy_metrics(flow)
        with self._lock:
            self._history.append(flow)
            if len(self._history) > self.settings.history_limit:
                del self._history[: len(self._history) - self.settings.history_limit]
        session_id = self._session_id
        if not session_id:
            session_id = "proxy_recovered_" + utc_now().replace(":", "").replace("-", "")
            try:
                self.history_store.start_session(session_id, *self.address, started_at=flow.started_at)
                self.history_store.finish_session(session_id)
            except ArenyxaError:
                LOGGER.exception("Could not create recovered Proxy Suite session")
        persistence_mode = self._persist_completed_flow(session_id, flow)
        self._emit("flow", flow)
        self._record_persistence_backpressure(flow, persistence_mode)

    def _intercept(self, flow: ProxyFlow, phase: str, raw: bytes) -> tuple[str, bytes]:
        decision = self.rule_engine.evaluate(phase, flow.method, flow.host, flow.url, raw)
        if decision is not None:
            if decision.rule_id:
                flow.rewrite_rule_ids.append(decision.rule_id)
            self._emit("rule", {
                "flow_id": flow.id,
                "phase": phase,
                "rule_id": decision.rule_id,
                "rule_name": decision.rule_name,
                "action": decision.action.value,
            })
            if decision.action is InterceptAction.ALLOW:
                return "forward", raw
            if decision.action is InterceptAction.BLOCK:
                return "drop", raw
            if decision.action is InterceptAction.MODIFY:
                return "forward", decision.raw
        should_intercept = (
            decision is not None and decision.action is InterceptAction.PAUSE
        ) or (self.settings.intercept_requests if phase == "request" else self.settings.intercept_responses)
        if not should_intercept:
            return "forward", raw
        item = PendingIntercept(uuid.uuid4().hex, flow.id, phase, utc_now(), raw, flow.method, flow.host, flow.target)
        with self._lock:
            self._pending[item.id] = item
        self._emit("intercept", item.snapshot())
        item.event.wait(timeout=float(self.settings.intercept_timeout_seconds))
        with self._lock:
            self._pending.pop(item.id, None)
        if not item.event.is_set():
            return "forward", raw
        return item.action, item.modified_raw if item.modified_raw is not None else raw

    def _handle_client(self, sock: socket.socket, client_address: tuple[Any, ...]) -> None:
        client = str(client_address[0]) if client_address else ""
        try:
            sock.settimeout(float(self.settings.read_timeout_seconds))
            head, rest = _read_head(sock, self.settings.max_header_bytes)
            if not head:
                return
            start_line, headers = _parse_head(head)
            parts = start_line.split(" ", 2)
            if len(parts) != 3:
                _send_error(sock, 400, "Bad Request")
                return
            method, target, version = parts
            try:
                expects_continue = _expects_continue(headers)
            except ValueError:
                _send_error(sock, 417, "Expectation Failed")
                return
            if method.upper() == "CONNECT":
                if expects_continue:
                    _send_error(sock, 417, "Expectation Failed")
                    return
                self._handle_connect(sock, client, target)
                return
            if expects_continue:
                sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            body = _read_message_body(sock, headers, rest, self.settings.max_message_bytes)
            raw = _assemble_message(start_line, headers, body)
            self._handle_http(sock, client, raw, scheme_hint="http")
        except ValueError as exc:
            try:
                _send_error(sock, 400, "Bad Request", str(exc))
            except OSError:
                record_current_exception(__name__, 'InterceptingProxy._handle_client:781')
        except (ConnectionError, OSError, ssl.SSLError) as exc:
            try:
                _send_error(sock, 502, "Proxy Error", str(exc))
            except OSError:
                record_current_exception(__name__, 'InterceptingProxy._handle_client:786')

    def _handle_connect(self, client_sock: socket.socket, client: str, target: str) -> None:
        host, port = _split_host_port(target, 443)
        started = time.monotonic()
        flow = self._new_flow(client, "https", "CONNECT", host, port, "/")
        flow.tunnel = not self.settings.tls_interception
        flow.request_raw = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("latin-1")
        flow.request_bytes = len(flow.request_raw)
        if not self.settings.tls_interception:
            try:
                with self.network_guard.connection_candidates(host) as connect_hosts:
                    upstream = _connect_validated_candidates(connect_hosts, port, float(self.settings.connect_timeout_seconds))
                    try:
                        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Arenyxa\r\n\r\n")
                        flow.status = 200
                        flow.reason = "Connection Established"
                        sent_up, sent_down = _relay(client_sock, upstream, float(self.settings.read_timeout_seconds))
                        flow.request_bytes += sent_up
                        flow.response_bytes = sent_down
                    finally:
                        try:
                            upstream.close()
                        except OSError:
                            record_current_exception(__name__, 'InterceptingProxy._handle_connect:810')
            except (OSError, ssl.SSLError, ArenyxaError) as exc:
                flow.error = str(exc)
                if flow.status is None:
                    flow.status = 502
                raise
            finally:
                self._complete(flow, started)
            return
        try:
            cert_path, key_path = self.ca.certificate_for_host(host)
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Arenyxa\r\n\r\n")
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_2
            server_context.set_alpn_protocols(["http/1.1"])
            server_context.load_cert_chain(str(cert_path), str(key_path))
            tls_client = server_context.wrap_socket(client_sock, server_side=True)
            flow.tls_intercepted = True
            flow.status = 200
            flow.reason = "Connection Established"
            self._complete(flow, started)
            self._handle_tls_http(tls_client, client, host, port)
        except (OSError, ssl.SSLError, ValueError, ArenyxaError) as exc:
            flow.error = str(exc)
            if not flow.completed_at:
                self._complete(flow, started)
            raise

    def _handle_tls_http(self, client_sock: ssl.SSLSocket, client: str, host: str, port: int) -> None:
        try:
            client_sock.settimeout(float(self.settings.read_timeout_seconds))
            try:
                head, rest = _read_head(client_sock, self.settings.max_header_bytes)
                if not head:
                    return
                start_line, headers = _parse_head(head)
                parts = start_line.split(" ", 2)
                if len(parts) != 3:
                    _send_error(client_sock, 400, "Bad Request")
                    return
                try:
                    expects_continue = _expects_continue(headers)
                except ValueError:
                    _send_error(client_sock, 417, "Expectation Failed")
                    return
                if expects_continue:
                    client_sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                body = _read_message_body(client_sock, headers, rest, self.settings.max_message_bytes)
                raw = _assemble_message(start_line, headers, body)
                self._handle_http(client_sock, client, raw, scheme_hint="https", fixed_destination=(host, port))
            except ValueError as exc:
                _send_error(client_sock, 400, "Bad Request", str(exc))
        finally:
            try:
                client_sock.close()
            except OSError:
                record_current_exception(__name__, 'InterceptingProxy._handle_tls_http:866')

    def _prepare_downstream_response(
        self,
        flow: ProxyFlow,
        response: bytes,
        method: str,
        host: str,
        origin_target: str,
    ) -> bytes:
        """Apply response rules/interception and synchronize the persisted summary."""
        response_line, _response_headers, _response_body = _parse_raw_message(response)
        status_parts = response_line.split(" ", 2)
        if len(status_parts) >= 2:
            try:
                flow.status = int(status_parts[1])
            except ValueError:
                flow.status = None
            flow.reason = status_parts[2] if len(status_parts) > 2 else ""
        response, response_rule_ids = self._apply_match_replace(response, "response", method, host, origin_target)
        flow.rewrite_rule_ids.extend(response_rule_ids)
        response_action, response_bytes = self._intercept(flow, "response", response)
        if response_action == "drop":
            flow.dropped = True
            response_bytes = _error_response(502, "Response dropped by Arenyxa Proxy")
            flow.status = 502
            flow.reason = "Response dropped by Arenyxa Proxy"
        else:
            try:
                edited_line, _edited_headers, _edited_body = _parse_raw_message(response_bytes)
                edited_parts = edited_line.split(" ", 2)
                if len(edited_parts) >= 2 and edited_parts[1].isdigit():
                    flow.status = int(edited_parts[1])
                    flow.reason = edited_parts[2] if len(edited_parts) > 2 else ""
            except ValueError:
                record_current_exception(__name__, 'InterceptingProxy._prepare_downstream_response:901')
        flow.response_raw = response_bytes
        flow.response_bytes = len(response_bytes)
        return response_bytes

    def _handle_http(
        self,
        client_sock: socket.socket,
        client: str,
        raw_request: bytes,
        scheme_hint: str,
        fixed_destination: tuple[str, int] | None = None,
    ) -> None:
        started = time.monotonic()
        start_line, headers, body = _parse_raw_message(raw_request)
        parts = start_line.split(" ", 2)
        if len(parts) != 3:
            _send_error(client_sock, 400, "Bad Request")
            return
        method, request_target, version = parts
        scheme, host, port, origin_target = _request_destination(request_target, headers, scheme_hint, fixed_destination)
        flow = self._new_flow(client, scheme, method.upper(), host, port, origin_target)
        normalized = _normalize_forward_request(method, origin_target, version, headers, body, host, port, scheme)
        flow.request_raw = normalized
        flow.request_bytes = len(normalized)
        if scheme == "https":
            flow.tls_intercepted = True
        action, intercepted = self._intercept(flow, "request", normalized)
        if action == "drop":
            flow.dropped = True
            flow.status = 403
            flow.reason = "Dropped by Arenyxa Proxy"
            response = _error_response(403, "Dropped by Arenyxa Proxy")
            flow.response_raw = response
            flow.response_bytes = len(response)
            client_sock.sendall(response)
            self._complete(flow, started)
            return
        try:
            intercepted, request_rule_ids = self._apply_match_replace(intercepted, "request", method, host, origin_target)
            flow.rewrite_rule_ids.extend(request_rule_ids)
            start_line, headers, body = _parse_raw_message(intercepted)
            method, request_target, version = start_line.split(" ", 2)
            scheme, host, port, origin_target = _request_destination(request_target, headers, scheme, fixed_destination)
            flow.method = method.upper()
            flow.scheme = scheme
            flow.host = host
            flow.port = port
            flow.target = origin_target
            normalized = _normalize_forward_request(method, origin_target, version, headers, body, host, port, scheme)
            flow.request_raw = normalized
            flow.request_bytes = len(normalized)
            auto = self._autoresponder_response(method, host, origin_target)
            if auto is not None:
                rule, response = auto
                flow.response_raw = response
                flow.response_bytes = len(response)
                flow.status = rule.status
                flow.reason = rule.reason or "Arenyxa AutoResponder"
                client_sock.sendall(response)
                return
            dlp = self._dlp_decision(scheme, host, port, origin_target, headers, body)
            if not dlp.allowed:
                flow.dropped = True
                flow.status = 403
                flow.reason = "Blocked by DLP"
                response = _error_response(403, "Blocked by Arenyxa DLP")
                flow.response_raw = response
                flow.response_bytes = len(response)
                client_sock.sendall(response)
                self._emit("dlp", {
                    "flow_id": flow.id, "host": dlp.destination_host,
                    "finding_kinds": sorted({item.kind for item in dlp.findings}),
                })
                return
            response = self._forward_upstream(scheme, host, port, method, normalized)
            response_bytes = self._prepare_downstream_response(flow, response, method, host, origin_target)
            client_sock.sendall(response_bytes)
        except (OSError, ssl.SSLError, ValueError, ArenyxaError) as exc:
            flow.error = str(exc)
            if flow.status is None:
                flow.status = 502
                flow.reason = "Proxy Error"
            error_response = _error_response(502, "Proxy Error", str(exc))
            flow.response_raw = error_response
            flow.response_bytes = len(error_response)
            try:
                client_sock.sendall(error_response)
            except OSError:
                record_current_exception(__name__, 'InterceptingProxy._handle_http:990')
        finally:
            self._complete(flow, started)
