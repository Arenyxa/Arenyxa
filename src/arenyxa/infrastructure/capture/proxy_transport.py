from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import ipaddress
import os
import select
import socket
import socketserver
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from arenyxa.infrastructure.capture.proxy import InterceptingProxy


_HTTP_TOKEN_CHARS = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_FORBIDDEN_TRAILER_FIELDS = {
    "authorization",
    "connection",
    "content-length",
    "host",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class _Receivable(Protocol):
    def recv(self, size: int) -> bytes: ...


class _ExhaustedInput:
    @staticmethod
    def recv(_size: int) -> bytes:
        return b""

class _ProxyTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    engine: InterceptingProxy

class _ProxyTCPServerV6(_ProxyTCPServer):
    address_family = socket.AF_INET6

class _ProxyRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.engine._client_started(self.request)
        try:
            self.server.engine._handle_client(self.request, self.client_address)
        finally:
            self.server.engine._client_finished(self.request)

def _is_loopback_host(host: str) -> bool:
    text = str(host).strip().casefold()
    if text == "localhost":
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False

def _secure_write(path: Path, data: bytes, public: bool = False) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    mode = 0o644 if public else 0o600
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(str(temp), flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                record_current_exception(__name__, '_secure_write:82')
        try:
            os.chmod(temp, mode)
        except OSError:
            record_current_exception(__name__, '_secure_write:86')
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            record_current_exception(__name__, '_secure_write:92')

def _read_head(sock: socket.socket, limit: int, initial: bytes = b"") -> tuple[bytes, bytes]:
    if limit < 4:
        raise ValueError("HTTP header limit is too small")
    buffer = bytearray(initial)
    marker = b"\r\n\r\n"
    while marker not in buffer:
        if len(buffer) > limit:
            raise ValueError("HTTP headers exceeded configured limit")
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffer.extend(chunk)
    index = buffer.find(marker)
    if index < 0:
        return bytes(buffer), b""
    if index + len(marker) > limit:
        raise ValueError("HTTP headers exceeded configured limit")
    end = index + len(marker)
    return bytes(buffer[:end]), bytes(buffer[end:])

def _parse_head(head: bytes) -> tuple[str, list[tuple[str, str]]]:
    if not head.endswith(b"\r\n\r\n"):
        raise ValueError("HTTP headers are not terminated")
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        raise ValueError("HTTP start line is missing")
    if any(ord(character) < 32 or ord(character) == 127 for character in lines[0]):
        raise ValueError("HTTP start line contains a control character")
    if len(lines) > 1026:
        raise ValueError("HTTP header count exceeded the safety limit")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t":
            raise ValueError("Obsolete folded HTTP headers are not accepted")
        name, separator, value = line.partition(":")
        if not separator or not name or any(character not in _HTTP_TOKEN_CHARS for character in name):
            raise ValueError("Malformed HTTP header")
        if any((ord(character) < 32 and character != "\t") or ord(character) == 127 for character in value):
            raise ValueError("HTTP header value contains a control character")
        headers.append((name, value.strip(" \t")))
    return lines[0], headers

def _header(headers: list[tuple[str, str]], name: str) -> str:
    wanted = name.casefold()
    for key, value in headers:
        if key.casefold() == wanted:
            return value
    return ""


def _header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    wanted = name.casefold()
    return [value for key, value in headers if key.casefold() == wanted]


def _content_length(headers: list[tuple[str, str]]) -> int | None:
    values: list[str] = []
    for raw in _header_values(headers, "Content-Length"):
        values.extend(part.strip() for part in raw.split(","))
    if not values:
        return None
    if any(not value or not value.isascii() or not value.isdigit() for value in values):
        raise ValueError("Invalid Content-Length")
    lengths = {int(value, 10) for value in values}
    if len(lengths) != 1:
        raise ValueError("Conflicting Content-Length headers")
    return lengths.pop()


def _transfer_codings(headers: list[tuple[str, str]]) -> tuple[str, ...]:
    values: list[str] = []
    for raw in _header_values(headers, "Transfer-Encoding"):
        values.extend(part.strip() for part in raw.split(","))
    if not values:
        return ()
    codings: list[str] = []
    for value in values:
        coding = value.split(";", 1)[0].strip().casefold()
        if not coding or any(character not in _HTTP_TOKEN_CHARS for character in coding):
            raise ValueError("Invalid Transfer-Encoding")
        codings.append(coding)
    if codings[-1] != "chunked" or codings.count("chunked") != 1:
        raise ValueError("Unsupported or ambiguous Transfer-Encoding framing")
    return tuple(codings)


def _message_framing(headers: list[tuple[str, str]]) -> tuple[bool, int | None]:
    codings = _transfer_codings(headers)
    length = _content_length(headers)
    if codings and length is not None:
        raise ValueError("Transfer-Encoding and Content-Length cannot be combined")
    return bool(codings), length


def _expects_continue(headers: list[tuple[str, str]]) -> bool:
    raw_values = _header_values(headers, "Expect")
    if not raw_values:
        return False
    expectations = [item.strip().casefold() for value in raw_values for item in value.split(",")]
    if not expectations or any(item != "100-continue" for item in expectations):
        raise ValueError("Unsupported HTTP expectation")
    return True

def _read_exact(sock: socket.socket, size: int, initial: bytes, limit: int) -> bytes:
    if size > limit:
        raise ValueError("HTTP message body exceeded configured limit")
    buffer = bytearray(initial[:size])
    while len(buffer) < size:
        chunk = sock.recv(min(65536, size - len(buffer)))
        if not chunk:
            raise ConnectionError("Connection closed before HTTP body completed")
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise ValueError("HTTP message body exceeded configured limit")
    return bytes(buffer)

def _read_chunked(sock: _Receivable, initial: bytes, limit: int) -> bytes:
    if limit < 0:
        raise ValueError("HTTP message body limit is invalid")
    buffer = bytearray(initial)
    if len(buffer) > limit:
        raise ValueError("Chunked HTTP body exceeded configured limit")
    position = 0
    decoded_bytes = 0
    trailer_count = 0

    def receive_until(marker: bytes, start: int, *, label: str) -> int:
        while True:
            index = buffer.find(marker, start)
            if index >= 0:
                return index
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError(f"Connection closed during {label}")
            buffer.extend(chunk)
            if len(buffer) > limit:
                raise ValueError("Chunked HTTP body exceeded configured limit")

    while True:
        line_end = receive_until(b"\r\n", position, label="chunked body")
        if line_end - position > 8192:
            raise ValueError("HTTP chunk-size line exceeded the safety limit")
        raw_line = bytes(buffer[position:line_end])
        if any(value < 32 or value == 127 for value in raw_line):
            raise ValueError("HTTP chunk-size line contains a control character")
        line = raw_line.split(b";", 1)[0].strip()
        if not line or len(line) > 16 or any(value not in b"0123456789abcdefABCDEF" for value in line):
            raise ValueError("Invalid HTTP chunk size")
        chunk_size = int(line, 16)
        position = line_end + 2
        if chunk_size > limit or decoded_bytes + chunk_size > limit:
            raise ValueError("Chunked HTTP body exceeded configured limit")
        if chunk_size == 0:
            while True:
                trailer_end = receive_until(b"\r\n", position, label="HTTP chunked trailer")
                trailer = bytes(buffer[position:trailer_end])
                position = trailer_end + 2
                if not trailer:
                    return bytes(buffer[:position])
                trailer_count += 1
                if trailer_count > 128:
                    raise ValueError("HTTP trailer count exceeded the safety limit")
                _start, parsed = _parse_head(b"TRAILER / HTTP/1.1\r\n" + trailer + b"\r\n\r\n")
                name = parsed[0][0].casefold()
                if name in _FORBIDDEN_TRAILER_FIELDS:
                    raise ValueError(f"Forbidden HTTP trailer field: {name}")
        required = position + chunk_size + 2
        while len(buffer) < required:
            chunk = sock.recv(min(65536, required - len(buffer)))
            if not chunk:
                raise ConnectionError("Connection closed during HTTP chunk")
            buffer.extend(chunk)
            if len(buffer) > limit:
                raise ValueError("Chunked HTTP body exceeded configured limit")
        if bytes(buffer[position + chunk_size : position + chunk_size + 2]) != b"\r\n":
            raise ValueError("Malformed HTTP chunk terminator")
        position = required
        decoded_bytes += chunk_size

def _read_message_body(sock: socket.socket, headers: list[tuple[str, str]], initial: bytes, limit: int) -> bytes:
    chunked, length = _message_framing(headers)
    if chunked:
        return _read_chunked(sock, initial, limit)
    if length is None:
        return b""
    return _read_exact(sock, length, initial, limit)

def _assemble_message(start_line: str, headers: list[tuple[str, str]], body: bytes) -> bytes:
    lines = [start_line, *[f"{name}: {value}" for name, value in headers], "", ""]
    return "\r\n".join(lines).encode("latin-1") + body

def _connect_validated_candidates(candidates: tuple[str, ...], port: int, timeout: float) -> socket.socket:
    last_error: OSError | None = None
    for connect_host in candidates:
        try:
            return socket.create_connection((connect_host, int(port)), timeout=float(timeout))
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError("No validated upstream address is available")

def _parse_raw_message(raw: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    marker = raw.find(b"\r\n\r\n")
    if marker < 0:
        raise ValueError("HTTP message is missing the header terminator")
    head = raw[: marker + 4]
    body = raw[marker + 4 :]
    start_line, headers = _parse_head(head)
    return start_line, headers, body

def _split_host_port(value: str, default_port: int) -> tuple[str, int]:
    text = str(value).strip()
    if not text:
        raise ValueError("Destination host is missing")
    if text.startswith("["):
        close = text.find("]")
        if close < 0:
            raise ValueError("Invalid IPv6 authority")
        host = text[1:close]
        suffix = text[close + 1 :]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                raise ValueError("Invalid IPv6 authority port")
            port = int(suffix[1:])
        else:
            port = default_port
        return _validated_host_port(host, port)
    if text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
        if not port_text.isdigit():
            raise ValueError("Invalid destination port")
        return _validated_host_port(host, int(port_text))
    return _validated_host_port(text, default_port)


def _validated_host_port(host: str, port: int) -> tuple[str, int]:
    normalized = str(host).strip().rstrip(".")
    if not normalized or any(ord(character) <= 32 or ord(character) == 127 for character in normalized):
        raise ValueError("Destination host is malformed")
    if int(port) < 1 or int(port) > 65535:
        raise ValueError("Destination port must be between 1 and 65535")
    return normalized, int(port)


def _format_authority(host: str, port: int, default_port: int) -> str:
    normalized, bounded_port = _validated_host_port(host, port)
    try:
        address = ipaddress.ip_address(normalized.split("%", 1)[0])
    except ValueError:
        authority_host = normalized.encode("idna").decode("ascii")
    else:
        authority_host = f"[{normalized}]" if address.version == 6 else normalized
    return authority_host if bounded_port == default_port else f"{authority_host}:{bounded_port}"

def _request_destination(
    request_target: str,
    headers: list[tuple[str, str]],
    scheme_hint: str,
    fixed_destination: tuple[str, int] | None,
) -> tuple[str, str, int, str]:
    if fixed_destination is not None:
        host, port = fixed_destination
        if request_target == "*":
            target = "*"
        elif request_target.startswith("/"):
            target = request_target
        else:
            parsed_target = urlsplit(request_target)
            if parsed_target.scheme.casefold() not in {"http", "https"} or not parsed_target.hostname:
                raise ValueError("Unsupported HTTP request-target form")
            target = parsed_target.path or "/"
            if parsed_target.query:
                target += "?" + parsed_target.query
        return "https", host, int(port), target
    parsed = urlsplit(request_target)
    if parsed.scheme.casefold() in {"http", "https"} and parsed.hostname:
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("HTTP request target must not contain user information")
        scheme = parsed.scheme.casefold()
        port = parsed.port or (443 if scheme == "https" else 80)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        return scheme, parsed.hostname, int(port), target
    if parsed.scheme:
        raise ValueError("Unsupported absolute request-target scheme")
    host_values = _header_values(headers, "Host")
    if len(host_values) != 1:
        raise ValueError("HTTP request requires exactly one Host header")
    authority = host_values[0]
    if not authority:
        raise ValueError("HTTP Host header is required")
    default_port = 443 if scheme_hint == "https" else 80
    host, port = _split_host_port(authority, default_port)
    if request_target == "*":
        target = "*"
    elif request_target.startswith("/"):
        target = request_target
    else:
        raise ValueError("Unsupported HTTP request-target form")
    return scheme_hint, host, int(port), target

def _normalize_forward_request(
    method: str,
    target: str,
    version: str,
    headers: list[tuple[str, str]],
    body: bytes,
    host: str,
    port: int,
    scheme: str,
) -> bytes:
    if not method or method != method.strip() or any(character not in _HTTP_TOKEN_CHARS for character in method):
        raise ValueError("Invalid HTTP method")
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ValueError("Only HTTP/1.0 and HTTP/1.1 forwarding are supported")
    transfer_chunked, _declared_length = _message_framing(headers)
    if transfer_chunked:
        try:
            encoded_body = _read_chunked(_ExhaustedInput(), body, len(body))
        except ConnectionError as exc:
            raise ValueError("Chunked HTTP body is incomplete") from exc
        if encoded_body != body:
            raise ValueError("Chunked HTTP body contains trailing bytes")
    host_values = _header_values(headers, "Host")
    if len(host_values) > 1:
        raise ValueError("Multiple Host headers are not accepted")
    connection_options: set[str] = set()
    for raw_value in _header_values(headers, "Connection"):
        for raw_option in raw_value.split(","):
            option = raw_option.strip().casefold()
            if not option or any(character not in _HTTP_TOKEN_CHARS for character in option):
                raise ValueError("Invalid Connection header option")
            connection_options.add(option)
    hop_by_hop = {
        "connection",
        "expect",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
        *connection_options,
    }
    filtered: list[tuple[str, str]] = []
    seen_host = False
    saw_content_length = False
    for name, value in headers:
        key = name.casefold()
        if key in hop_by_hop:
            continue
        if key == "host":
            if seen_host:
                continue
            seen_host = True
            default_port = 443 if scheme == "https" else 80
            authority = _format_authority(host, port, default_port)
            filtered.append(("Host", authority))
            continue
        if key == "content-length":
            if saw_content_length or transfer_chunked:
                continue
            saw_content_length = True
            filtered.append(("Content-Length", str(len(body))))
            continue
        filtered.append((name, value))
    if not seen_host:
        default_port = 443 if scheme == "https" else 80
        authority = _format_authority(host, port, default_port)
        filtered.insert(0, ("Host", authority))
    filtered.append(("Connection", "close"))
    if not transfer_chunked and body and not saw_content_length:
        filtered.append(("Content-Length", str(len(body))))
    return _assemble_message(f"{method} {target} {version}", filtered, body)

def _read_response(sock: socket.socket, request_method: str, header_limit: int, message_limit: int) -> bytes:
    pending = b""
    informational = 0
    while True:
        head, rest = _read_head(sock, header_limit, pending)
        if not head:
            raise ConnectionError("Upstream server returned no HTTP response")
        status_line, headers = _parse_head(head)
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or parts[0] not in {"HTTP/1.0", "HTTP/1.1"} or len(parts[1]) != 3 or not parts[1].isdigit():
            raise ValueError("Invalid upstream HTTP status line")
        status = int(parts[1])
        if 100 <= status < 200 and status != 101:
            informational += 1
            if informational > 8:
                raise ValueError("Upstream returned too many informational responses")
            if _transfer_codings(headers):
                raise ValueError("Informational response must not use Transfer-Encoding")
            pending = rest
            continue
        break
    if request_method == "HEAD" or 100 <= status < 200 or status in {204, 304}:
        return head
    chunked, length = _message_framing(headers)
    if chunked:
        body = _read_chunked(sock, rest, message_limit)
        return head + body
    if length is not None:
        body = _read_exact(sock, length, rest, message_limit)
        return head + body
    buffer = bytearray(rest)
    if len(buffer) > message_limit:
        raise ValueError("Upstream HTTP response exceeded configured limit")
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > message_limit:
            raise ValueError("Upstream HTTP response exceeded configured limit")
    return head + bytes(buffer)

def _relay(left: socket.socket, right: socket.socket, idle_timeout: float) -> tuple[int, int]:
    # Keep a bounded per-direction relay buffer large enough to absorb normal
    # full-duplex bursts without deadlocking peers that finish a write before
    # starting the opposite-direction read. The cap is still strict and keeps
    # memory use predictable under backpressure.
    max_pending_per_direction = 4 * 1024 * 1024
    left.setblocking(False)
    right.setblocking(False)
    last_activity = time.monotonic()
    up = 0
    down = 0
    left_readable = True
    right_readable = True
    left_write_open = True
    right_write_open = True
    pending_left = bytearray()
    pending_right = bytearray()
    while True:
        if not left_readable and not right_readable and not pending_left and not pending_right:
            break
        remaining = max(0.0, idle_timeout - (time.monotonic() - last_activity))
        if remaining <= 0:
            break
        read_wait: list[socket.socket] = []
        if left_readable and len(pending_right) < max_pending_per_direction:
            read_wait.append(left)
        if right_readable and len(pending_left) < max_pending_per_direction:
            read_wait.append(right)
        write_wait: list[socket.socket] = []
        if pending_left and left_write_open:
            write_wait.append(left)
        if pending_right and right_write_open:
            write_wait.append(right)
        exceptional_wait = [item for item in (left, right) if item in read_wait or item in write_wait]
        if not read_wait and not write_wait:
            break
        readable, writable, exceptional = select.select(
            read_wait,
            write_wait,
            exceptional_wait,
            min(1.0, remaining),
        )
        if exceptional:
            break
        for source in readable:
            try:
                target_buffer = pending_right if source is left else pending_left
                capacity = max_pending_per_direction - len(target_buffer)
                data = source.recv(min(65536, capacity))
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                data = b""
            if not data:
                if source is left:
                    left_readable = False
                else:
                    right_readable = False
                continue
            target_buffer.extend(data)
            last_activity = time.monotonic()
        for destination in writable:
            source_buffer = pending_left if destination is left else pending_right
            try:
                sent = destination.send(source_buffer)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                sent = 0
                if destination is left:
                    left_write_open = False
                    pending_left.clear()
                else:
                    right_write_open = False
                    pending_right.clear()
            if sent > 0:
                del source_buffer[:sent]
                if destination is left:
                    down += sent
                else:
                    up += sent
                last_activity = time.monotonic()
        if not left_readable and not pending_right and right_write_open:
            try:
                right.shutdown(socket.SHUT_WR)
            except OSError:
                record_current_exception(__name__, '_relay:603')
            right_write_open = False
        if not right_readable and not pending_left and left_write_open:
            try:
                left.shutdown(socket.SHUT_WR)
            except OSError:
                record_current_exception(__name__, '_relay:609')
            left_write_open = False
    return up, down

def _error_response(status: int, reason: str, detail: str = "") -> bytes:
    text = reason if not detail else f"{reason}\n{detail}"
    body = text.encode("utf-8", "replace")[:65536]
    headers = [
        f"HTTP/1.1 {int(status)} {reason}",
        "Content-Type: text/plain; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "Proxy-Agent: Arenyxa",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("latin-1", "replace") + body

def _send_error(sock: socket.socket, status: int, reason: str, detail: str = "") -> None:
    sock.sendall(_error_response(status, reason, detail))
