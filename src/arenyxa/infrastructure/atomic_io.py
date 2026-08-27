from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


def _fsync_directory(path: Path) -> None:
    





    if os.name == "nt":
        return
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        record_current_exception(__name__, '_fsync_directory:27')
    finally:
        os.close(fd)



def fsync_existing_file(path: Path) -> None:
    






    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    fd = os.open(Path(path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace_with_retry(source: Path, destination: Path) -> None:
    







    delays = (0.0, 0.015, 0.035, 0.075, 0.15, 0.25)
    last_error: OSError | None = None
    for index, delay in enumerate(delays):
        if delay:
            time.sleep(delay)
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            last_error = exc
                                                                                            
                                                                                          
                                                                                            
            transient = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in {5, 32, 33}
            if not transient or index == len(delays) - 1:
                raise
    assert last_error is not None
    raise last_error


def read_bytes_limited(path: Path, max_bytes: int) -> bytes:
    
    path = Path(path)
    limit = max(1, int(max_bytes))
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"file exceeds {limit} byte limit")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"file exceeds {limit} byte limit")
    return payload


def read_text_limited(path: Path, max_bytes: int, *, encoding: str = "utf-8") -> str:
    return read_bytes_limited(Path(path), max_bytes).decode(encoding)

def atomic_write_bytes(path: Path, payload: bytes, *, mode: int | None = None) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(raw)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if mode is not None:
                try:
                    os.chmod(temporary, mode)
                except OSError:
                    record_current_exception(__name__, 'atomic_write_bytes:111')
            _replace_with_retry(temporary, path)
            _fsync_directory(path.parent)
            temporary = None
        except Exception:
            try:
                os.close(fd)
            except OSError:
                record_current_exception(__name__, 'atomic_write_bytes:119')
            raise
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                record_current_exception(__name__, 'atomic_write_bytes:126')


def atomic_write_text(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    newline: str | None = None,
    mode: int | None = None,
) -> None:
    if newline is not None:
                                                                                            
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if newline != "\n":
            text = text.replace("\n", newline)
    atomic_write_bytes(Path(path), text.encode(encoding), mode=mode)


def atomic_write_json(
    path: Path,
    value: Any,
    *,
    ensure_ascii: bool = False,
    indent: int | None = 2,
    mode: int | None = None,
) -> None:
    payload = json.dumps(value, ensure_ascii=ensure_ascii, indent=indent, default=str)
    atomic_write_text(Path(path), payload, mode=mode)
