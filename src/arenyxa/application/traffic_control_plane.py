from __future__ import annotations

import hashlib
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from arenyxa.application.job_system import JobExecutionContext, JobSystem
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine
from arenyxa.infrastructure.capture.protocol_registry import global_protocol_registry
from arenyxa.security import SecurityKernel, Session


class TrafficControlPlane:
    """Unified v8 network/protocol/proxy application service.

    The service deliberately owns authorization, resource bounds, path confinement and
    long-running Job System handoff. GUI/CLI/Server/Worker surfaces can share this layer
    without duplicating traffic-domain policy or calling infrastructure objects directly.
    """

    _MAX_PROTOCOL_QUERY = 256
    _MAX_PROTOCOL_LIMIT = 5_000
    _MAX_FIELD_LIMIT = 10_000
    _MAX_DECODE_BYTES = 4 * 1024 * 1024
    _MAX_PROXY_PAGE_SIZE = 1_000

    def __init__(
        self,
        *,
        paths: Any,
        store: Any,
        security: SecurityKernel,
        jobs: JobSystem,
        capture: Any,
        proxy: Any = None,
        mitm: Any = None,
        network_intelligence: Any = None,
    ) -> None:
        self.paths = paths
        self.store = store
        self.security = security
        self.jobs = jobs
        self.capture = capture
        self.proxy = proxy
        self.mitm = mitm
        self.network_intelligence = network_intelligence

    # ------------------------------------------------------------------
    # Network / capture
    # ------------------------------------------------------------------
    def status(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        self._require(session, "data.read", "network:status", surface)
        capture = self.capture_status(session=session, surface=surface, authorize=False)
        proxy = None if self.proxy is None else self._normalize(self.proxy.status())
        mitm = None if self.mitm is None else self._normalize(self.mitm.status())
        intelligence: dict[str, Any] | None = None
        active = getattr(self.capture, "session", None)
        if self.network_intelligence is not None:
            try:
                intelligence = self._normalize(
                    self.network_intelligence.live_snapshot("" if active is None else active.id)
                )
            except (OSError, RuntimeError, TypeError, ValueError, LookupError) as exc:
                intelligence = {
                    "status": "degraded",
                    "error_code": "NETWORK_INTELLIGENCE_SNAPSHOT_FAILED",
                    "error": f"{type(exc).__name__}: {exc}"[:512],
                }
        return {
            "schema": "arenyxa.traffic-control/v1",
            "capture": capture,
            "proxy": proxy,
            "mitm": mitm,
            "intelligence": intelligence,
        }

    def capture_status(
        self,
        *,
        session: Session | None,
        surface: str,
        authorize: bool = True,
    ) -> dict[str, Any]:
        if authorize:
            self._require(session, "data.read", "capture:status", surface)
        health = getattr(self.capture, "health_snapshot", None)
        if callable(health):
            return self._normalize(health())
        active = getattr(self.capture, "session", None)
        return {
            "active": active is not None,
            "session": None if active is None else self._normalize(active),
        }

    def stop_capture(self, *, session: Session | None, surface: str, cancelled: bool = False) -> dict[str, Any]:
        self._require(session, "capture.run", "capture:active", surface)
        active = getattr(self.capture, "session", None)
        if active is None:
            raise ArenyxaError("CAPTURE_NOT_ACTIVE", "No capture session is active", domain="CAPTURE")
        result = self.capture.stop(cancelled=bool(cancelled))
        return {"stopped": True, "session": self._normalize(result)}

    def list_capture_events(
        self,
        capture_id: str,
        *,
        session: Session | None,
        surface: str,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        identifier = self._identifier(capture_id, "capture id")
        bounded = max(1, min(10_000, int(limit)))
        self._require(session, "data.read", f"capture:{identifier}", surface)
        return list(self.store.iter_network_events(identifier, bounded))

    def submit_capture_analysis(
        self,
        capture_path: Path | str,
        *,
        session: Session | None,
        surface: str,
        display_filter: str = "",
        timeout_seconds: float = 300.0,
    ) -> dict[str, Any]:
        path = self._confined_input_path(capture_path)
        expression = str(display_filter or "").strip()
        if len(expression) > 4096:
            raise ValueError("display filter exceeds 4096 characters")

        def operation(execution: JobExecutionContext) -> dict[str, Any]:
            execution.report_progress(0.05, "Inspecting capture")
            engine = PacketAnalysisEngine()
            info = engine.capture_info(path)
            execution.report_progress(0.35, "Computing bounded packet statistics")
            stats = engine.full_statistics(path, display_filter=expression)
            execution.report_progress(0.95, "Finalizing analysis")
            return {
                "path": str(path),
                "sha256": self._sha256_file(path),
                "capture": self._normalize(info),
                "statistics": self._normalize(stats),
                "display_filter": expression,
            }

        return self.jobs.submit(
            "capture-analysis",
            operation,
            session=session,
            capability="data.read",
            resource=f"capture-file:{path.name}",
            surface=surface,
            timeout_seconds=timeout_seconds,
            workload="heavy",
        )

    # ------------------------------------------------------------------
    # Protocol intelligence
    # ------------------------------------------------------------------
    def protocol_catalog(
        self,
        *,
        session: Session | None,
        surface: str,
        contains: str = "",
        limit: int = 500,
    ) -> dict[str, Any]:
        needle = self._bounded_query(contains)
        bounded = max(1, min(self._MAX_PROTOCOL_LIMIT, int(limit)))
        self._require(session, "data.read", "protocol:catalog", surface)
        engine = PacketAnalysisEngine()
        rows = engine.unified_protocol_catalog(contains=needle, limit=bounded)
        return {
            "external_available": bool(engine.available),
            "registry": self._normalize(engine.unified_protocol_registry(field_limit=bounded)),
            "count": len(rows),
            "protocols": rows,
        }

    def protocol_fields(
        self,
        *,
        session: Session | None,
        surface: str,
        contains: str = "",
        protocol: str = "",
        limit: int = 500,
    ) -> dict[str, Any]:
        needle = self._bounded_query(contains)
        protocol_name = self._bounded_query(protocol, maximum=128)
        bounded = max(1, min(self._MAX_FIELD_LIMIT, int(limit)))
        self._require(session, "data.read", "protocol:fields", surface)
        engine = PacketAnalysisEngine()
        rows = engine.unified_field_catalog(contains=needle, protocol=protocol_name, limit=bounded)
        return {
            "external_available": bool(engine.available),
            "registry": self._normalize(engine.unified_protocol_registry(field_limit=min(bounded, 5000))),
            "count": len(rows),
            "fields": rows,
        }

    def decode_protocol(
        self,
        protocol: str,
        payload: bytes | bytearray | memoryview,
        *,
        session: Session | None,
        surface: str,
    ) -> dict[str, Any]:
        name = self._bounded_query(protocol, maximum=128)
        if not name:
            raise ValueError("protocol name is required")
        raw = bytes(payload)
        if len(raw) > self._MAX_DECODE_BYTES:
            raise ArenyxaError(
                "PROTOCOL_BUDGET_EXCEEDED",
                "Protocol decode payload exceeds the 4 MiB control-plane budget",
                domain="PROTOCOL",
                context={"size": len(raw), "limit": self._MAX_DECODE_BYTES},
            )
        self._require(session, "data.read", f"protocol:{name}", surface)
        decoded = global_protocol_registry().decode(name, raw)
        return {
            "protocol": name,
            "size": len(raw),
            "decoded": decoded is not None,
            "result": self._normalize(decoded),
        }

    # ------------------------------------------------------------------
    # Proxy / MITM
    # ------------------------------------------------------------------
    def proxy_status(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        engine = self._proxy_engine()
        self._require(session, "data.read", "proxy:status", surface)
        return self._normalize(engine.status())

    def start_proxy(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        engine = self._proxy_engine()
        self._require(session, "capture.run", "proxy:listener", surface)
        host, port = engine.start()
        return {"running": True, "host": host, "port": int(port), "status": self._normalize(engine.status())}

    def stop_proxy(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        engine = self._proxy_engine()
        self._require(session, "capture.run", "proxy:listener", surface)
        engine.stop()
        return self._normalize(engine.status())

    def proxy_history(
        self,
        *,
        session: Session | None,
        surface: str,
        page: int = 1,
        page_size: int = 100,
        query: str = "",
        proxy_session_id: str = "",
    ) -> dict[str, Any]:
        engine = self._proxy_engine()
        self._require(session, "data.read", "proxy:history", surface)
        page_value = max(1, int(page))
        size_value = max(1, min(self._MAX_PROXY_PAGE_SIZE, int(page_size)))
        needle = self._bounded_query(query, maximum=1024)
        session_id = self._bounded_query(proxy_session_id, maximum=256)
        result = engine.history_page(page=page_value, page_size=size_value, query=needle, session_id=session_id)
        normalized = self._normalize(result)
        if not isinstance(normalized, dict):
            raise RuntimeError("proxy history returned an invalid result")
        return normalized

    def inspect_proxy_flow(self, flow_id: str, *, session: Session | None, surface: str) -> dict[str, Any]:
        engine = self._proxy_engine()
        identifier = self._identifier(flow_id, "flow id")
        self._require(session, "data.read", f"proxy:flow:{identifier}", surface)
        flow = engine.get_flow(identifier)
        if flow is None:
            raise ArenyxaError("FLOW_NOT_FOUND", "Proxy flow was not found", domain="PROXY")
        return {
            "flow": self._normalize(flow),
            "inspection": self._normalize(engine.inspect_flow(identifier)),
        }

    def submit_proxy_har_export(
        self,
        destination: Path | str,
        *,
        session: Session | None,
        surface: str,
        redact_sensitive: bool = True,
        timeout_seconds: float = 120.0,
    ) -> dict[str, Any]:
        engine = self._proxy_engine()
        target = self._confined_export_path(destination, default_suffix=".har")

        def operation(execution: JobExecutionContext) -> dict[str, Any]:
            execution.report_progress(0.1, "Reading bounded proxy history")
            exported = engine.export_har(target, redact_sensitive=bool(redact_sensitive))
            execution.report_progress(0.95, "Finalizing HAR")
            return {
                "path": str(exported),
                "redacted": bool(redact_sensitive),
                "sha256": self._sha256_file(Path(exported)),
            }

        return self.jobs.submit(
            "proxy-har-export",
            operation,
            session=session,
            capability="data.export",
            resource="proxy:export:har",
            surface=surface,
            timeout_seconds=timeout_seconds,
            workload="write",
        )

    def mitm_status(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        engine = self._mitm_engine()
        self._require(session, "data.read", "mitm:status", surface)
        return self._normalize(engine.status())

    def start_mitm(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        engine = self._mitm_engine()
        self._require(session, "capture.run", "mitm:listener", surface)
        return self._normalize(engine.start())

    def stop_mitm(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        engine = self._mitm_engine()
        self._require(session, "capture.run", "mitm:listener", surface)
        engine.stop()
        return self._normalize(engine.status())

    def mitm_events(
        self,
        *,
        session: Session | None,
        surface: str,
        query: str = "",
        protocol: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        engine = self._mitm_engine()
        self._require(session, "data.read", "mitm:events", surface)
        needle = self._bounded_query(query, maximum=1024)
        protocol_name = self._bounded_query(protocol, maximum=128)
        bounded = max(1, min(5000, int(limit)))
        rows = engine.events(query=needle, protocol=protocol_name)
        return [self._normalize(item) for item in rows[-bounded:]]

    # ------------------------------------------------------------------
    # Internal policy / bounds
    # ------------------------------------------------------------------
    def _require(self, session: Session | None, capability: str, resource: str, surface: str) -> None:
        self.security.require(
            session,
            capability,
            resource,
            context={"surface": "application-control-plane", "entry_surface": str(surface).strip().casefold()[:64]},
        )

    def _proxy_engine(self) -> Any:
        if self.proxy is None:
            raise ArenyxaError("PROXY_UNAVAILABLE", "Proxy runtime is unavailable", domain="PROXY")
        return self.proxy

    def _mitm_engine(self) -> Any:
        if self.mitm is None:
            raise ArenyxaError("MITM_UNAVAILABLE", "MITM runtime is unavailable", domain="MITM")
        return self.mitm

    def _confined_input_path(self, value: Path | str) -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = Path(self.paths.projects) / candidate
        resolved = candidate.resolve(strict=True)
        roots = (Path(self.paths.projects).resolve(), Path(self.paths.captures).resolve())
        if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
            raise ArenyxaError(
                "TRAFFIC_PATH_OUTSIDE_ALLOWED_ROOT",
                "Capture analysis input must be inside the Projects or Captures roots",
                domain="NETWORK",
            )
        if not resolved.is_file():
            raise FileNotFoundError(resolved)
        return resolved

    def _confined_export_path(self, value: Path | str, *, default_suffix: str = "") -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = Path(self.paths.exports) / candidate
        if default_suffix and not candidate.suffix:
            candidate = candidate.with_suffix(default_suffix)
        root = Path(self.paths.exports).resolve()
        parent = candidate.parent.resolve(strict=False)
        target = (parent / candidate.name).resolve(strict=False)
        if not (target == root or target.is_relative_to(root)):
            raise ArenyxaError(
                "TRAFFIC_EXPORT_PATH_OUTSIDE_ROOT",
                "Traffic exports must remain inside the Arenyxa exports root",
                domain="NETWORK",
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    @classmethod
    def _bounded_query(cls, value: str, *, maximum: int | None = None) -> str:
        limit = cls._MAX_PROTOCOL_QUERY if maximum is None else max(1, int(maximum))
        text = str(value or "").strip()
        if len(text) > limit:
            raise ValueError(f"query exceeds {limit} characters")
        if any(ord(ch) < 32 and ch not in "\t" for ch in text):
            raise ValueError("query contains control characters")
        return text

    @staticmethod
    def _identifier(value: str, label: str) -> str:
        text = str(value or "").strip()
        if not text or len(text) > 256 or any(ord(ch) < 33 for ch in text):
            raise ValueError(f"{label} must be a non-empty token up to 256 characters")
        return text

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    @classmethod
    def _normalize(cls, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, Enum):
            return value.value
        if is_dataclass(value):
            return cls._normalize(asdict(value))
        snapshot = getattr(value, "snapshot", None)
        if callable(snapshot):
            return cls._normalize(snapshot())
        if isinstance(value, dict):
            return {str(key): cls._normalize(item) for key, item in value.items()}
        if isinstance(value, (tuple, list, set, frozenset)):
            return [cls._normalize(item) for item in value]
        return str(value)
