from __future__ import annotations

import sys
from typing import Any


def console_write(
    *values: Any,
    error: bool = False,
    sep: str = " ",
    end: str = "\n",
    flush: bool = False,
) -> None:
    """Write intentional CLI/protocol output without using ad-hoc ``print`` calls.

    Operational diagnostics belong in ``logging``.  This boundary is only for user-visible CLI
    output or line-oriented worker protocols that intentionally use stdout/stderr.
    """
    stream = sys.stderr if error else sys.stdout
    if stream is None:
        return
    text = sep.join(str(value) for value in values) + end
    try:
        stream.write(text)
    except UnicodeEncodeError:
        # Redirected Windows consoles may not support Unicode diagnostic symbols.
        encoding = getattr(stream, "encoding", None) or "utf-8"
        stream.write(text.encode(encoding, errors="backslashreplace").decode(encoding))
    if flush:
        stream.flush()
