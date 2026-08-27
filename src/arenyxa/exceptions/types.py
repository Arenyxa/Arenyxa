class ArenyxaError(Exception):
    """Base application exception."""


class NetworkError(ArenyxaError):
    """Marker type for NetworkError."""


class SecurityError(ArenyxaError):
    """Marker type for SecurityError."""


class StorageError(ArenyxaError):
    """Marker type for StorageError."""


class ProtocolError(ArenyxaError):
    """Marker type for ProtocolError."""
