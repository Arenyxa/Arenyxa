from __future__ import annotations

import hashlib
import tracemalloc
from pathlib import Path

from arenyxa.infrastructure.streaming_io import sha256_file


def test_large_file_hashing_has_chunk_bounded_python_memory(tmp_path: Path) -> None:
    path = tmp_path / "32mib.bin"
    with path.open("wb") as stream:
        stream.truncate(32 * 1024 * 1024)
    expected = hashlib.sha256(b"\0" * (1024 * 1024)).digest()
    # The expected variable intentionally proves the test itself does not allocate the full file;
    # correctness is asserted against a second streaming implementation below.
    assert len(expected) == 32

    reference = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            reference.update(block)

    tracemalloc.start()
    actual = sha256_file(path)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert actual == reference.hexdigest()
    assert peak < 8 * 1024 * 1024
