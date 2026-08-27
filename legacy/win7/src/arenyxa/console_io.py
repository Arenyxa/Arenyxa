from __future__ import annotations

import sys
from typing import Any, TextIO


def console_write(*values: Any, error: bool = False, sep: str = " ", end: str = "\n", flush: bool = False, file: TextIO = None) -> None:
    """Write intentional CLI/protocol output without using ad-hoc print calls."""
    stream = file if file is not None else (sys.stderr if error else sys.stdout)
    stream.write(sep.join(str(value) for value in values) + end)
    if flush:
        stream.flush()
