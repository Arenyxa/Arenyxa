from __future__ import annotations

class CommandRuntimeError(RuntimeError):
    def __init__(self, code: str, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.code = str(code)
        self.message = str(message)
        self.exit_code = int(exit_code)
