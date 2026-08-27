"""P1 transport safety helpers."""

from __future__ import annotations

import socket


DEFAULT_SOCKET_TIMEOUT = 30.0


def apply_socket_timeout(sock: socket.socket, timeout: float = DEFAULT_SOCKET_TIMEOUT) -> None:
    """Prevent indefinite blocking network operations."""
    sock.settimeout(timeout)
