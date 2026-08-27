from __future__ import annotations

import multiprocessing as mp
import re
from typing import Any

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError

DEFAULT_TIMEOUT_SECONDS = 1.25
MAX_TIMEOUT_SECONDS = 5.0
MAX_PATTERN_CHARS = 4096
MAX_INPUT_CHARS = 2 * 1024 * 1024
MAX_REPLACEMENT_CHARS = 64 * 1024


def _regex_error(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="REGEX", context=context)


@dataclass(frozen=True, slots=True)
class SafeRegexMatch:
    values: tuple[str | None, ...]

    def group(self, index: int = 0) -> str | None:
        try:
            return self.values[int(index)]
        except (TypeError, ValueError, IndexError) as exc:
            raise IndexError("regex group index is out of range") from exc


def _worker(connection, operation: str, pattern: str, text: str, replacement: str) -> None:
    try:
        if operation == "search":
            match = re.search(pattern, text)
            if match is None:
                connection.send(("ok", None))
            else:
                connection.send(("ok", (match.group(0),) + match.groups()))
        elif operation == "sub":
            connection.send(("ok", re.sub(pattern, replacement, text)))
        else:
            connection.send(("error", "REGEX_OPERATION_INVALID", "unsupported regex operation"))
    except re.error as exc:
        connection.send(("error", "REGEX_INVALID", str(exc)))
    except BaseException as exc:
                                                                                        
        connection.send(("error", "REGEX_EXECUTION_FAILED", type(exc).__name__))
    finally:
        connection.close()


def _bounded_inputs(pattern: str, text: str, replacement: str = "") -> tuple[str, str, str]:
    pattern = str(pattern)
    text = str(text)
    replacement = str(replacement)
    if len(pattern) > MAX_PATTERN_CHARS:
        raise _regex_error("REGEX_PATTERN_TOO_LARGE", "Regex pattern exceeds the safety limit")
    if len(text) > MAX_INPUT_CHARS:
        raise _regex_error("REGEX_INPUT_TOO_LARGE", "Regex input exceeds the safety limit")
    if len(replacement) > MAX_REPLACEMENT_CHARS:
        raise _regex_error("REGEX_REPLACEMENT_TOO_LARGE", "Regex replacement exceeds the safety limit")
    return pattern, text, replacement


def _run(operation: str, pattern: str, text: str, replacement: str, timeout_seconds: float) -> Any:
    pattern, text, replacement = _bounded_inputs(pattern, text, replacement)
    timeout = max(0.05, min(MAX_TIMEOUT_SECONDS, float(timeout_seconds)))
    context = mp.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker,
        args=(child, operation, pattern, text, replacement),
        name="ArenyxaRegexSandbox",
        daemon=True,
    )
    process.start()
    child.close()
    try:
        if not parent.poll(timeout):
            process.terminate()
            process.join(timeout=0.5)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join(timeout=0.5)
            raise _regex_error(
                "REGEX_TIMEOUT",
                "Regex execution exceeded the wall-clock safety limit",
                timeout_seconds=timeout,
            )
        try:
            payload = parent.recv()
        except EOFError as exc:
            raise _regex_error("REGEX_EXECUTION_FAILED", "Regex worker exited without a result") from exc
    finally:
        parent.close()
        if process.is_alive():
            process.terminate()
        process.join(timeout=0.5)
    if not isinstance(payload, tuple) or not payload:
        raise _regex_error("REGEX_EXECUTION_FAILED", "Regex worker returned an invalid result")
    if payload[0] == "ok":
        return payload[1]
    code = str(payload[1]) if len(payload) > 1 else "REGEX_EXECUTION_FAILED"
    message = str(payload[2]) if len(payload) > 2 else "Regex execution failed"
    raise _regex_error(code, message)


def safe_search(
    pattern: str,
    text: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> SafeRegexMatch | None:
    result = _run("search", pattern, text, "", timeout_seconds)
    if result is None:
        return None
    if not isinstance(result, tuple):
        raise _regex_error("REGEX_EXECUTION_FAILED", "Regex worker returned an invalid match")
    return SafeRegexMatch(tuple(None if item is None else str(item) for item in result))


def safe_sub(
    pattern: str,
    replacement: str,
    text: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    result = _run("sub", pattern, text, replacement, timeout_seconds)
    if not isinstance(result, str):
        raise _regex_error("REGEX_EXECUTION_FAILED", "Regex worker returned an invalid replacement")
    return result
