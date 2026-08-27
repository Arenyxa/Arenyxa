"""Bounded streaming primitives for hot paths and large evidence files."""

from __future__ import annotations

import hashlib
import mmap
import os
from collections.abc import Callable, Iterator
from typing import BinaryIO
from pathlib import Path

_DEFAULT_CHUNK_SIZE = 1024 * 1024


def iter_file_chunks(path: Path | str, *, chunk_size: int = _DEFAULT_CHUNK_SIZE) -> Iterator[bytes]:
    size = max(4096, min(16 * 1024 * 1024, int(chunk_size)))
    with Path(path).open("rb", buffering=0) as handle:
        while True:
            chunk = handle.read(size)
            if not chunk:
                return
            yield chunk


def sha256_file(path: Path | str, *, chunk_size: int = _DEFAULT_CHUNK_SIZE) -> str:
    """Hash arbitrarily large files with O(chunk_size) working memory."""

    digest = hashlib.sha256()
    for chunk in iter_file_chunks(path, chunk_size=chunk_size):
        digest.update(chunk)
    return digest.hexdigest()


def consume_stream_limited(
    stream: BinaryIO,
    *,
    limit: int,
    checkpoint: Callable[[], None] | None = None,
    chunk_size: int = 64 * 1024,
) -> bytes:
    """Read a bounded stream without the list-of-chunks + join peak-memory pattern."""

    if limit < 0:
        raise ValueError("limit must be non-negative")
    size = max(4096, min(4 * 1024 * 1024, int(chunk_size)))
    buffer = bytearray()
    while True:
        if checkpoint is not None:
            checkpoint()
        chunk = stream.read(size)
        if not chunk:
            break
        if len(buffer) + len(chunk) > limit:
            raise ValueError(f"stream exceeds {limit} byte limit")
        buffer.extend(chunk)
    return bytes(buffer)


def mmap_readonly(path: Path | str) -> mmap.mmap:
    """Return a read-only memory map for random access without copying the file into RAM."""

    resolved = Path(path)
    descriptor = os.open(resolved, os.O_RDONLY)
    try:
        return mmap.mmap(descriptor, length=0, access=mmap.ACCESS_READ)
    finally:
        os.close(descriptor)
