from __future__ import annotations

from arenyxa.compat import StrEnum


class TaskStatus(StrEnum):
    DRAFT = "draft"
    READY = "ready"
    ARCHIVED = "archived"
    DELETED = "deleted"


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CaptureState(StrEnum):
    IDLE = "idle"
    PREPARING = "preparing"
    CAPTURING = "capturing"
    PAUSED = "paused"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CaptureSource(StrEnum):
    BROWSER = "browser"
    SYSTEM = "system"
    HAR_IMPORT = "har_import"
    PCAP_IMPORT = "pcap_import"
    HTTP_RUNNER = "http_runner"


class SourceKind(StrEnum):
    HTTP = "http"
    BROWSER = "browser"
    API = "api"
    NETWORK = "network"
    HAR = "har"


class NetworkEntityKind(StrEnum):
    FLOW = "flow"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    DNS = "dns"
    TLS = "tls"
    WEBSOCKET = "websocket"


class Severity(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MaterialRole(StrEnum):
    SURFACE = "surface"
    GLASS = "glass"
    ELEVATED_GLASS = "elevated_glass"
    OVERLAY_GLASS = "overlay_glass"
    SOLID_FALLBACK = "solid_fallback"


class MotionIntent(StrEnum):
    ENTER = "enter"
    EXIT = "exit"
    EXPAND = "expand"
    COLLAPSE = "collapse"
    MOVE = "move"
    EMPHASIZE = "emphasize"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    LIVE_DATA = "live_data"


class WorkspaceRole(StrEnum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    VIEWER = "viewer"
