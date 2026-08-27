from __future__ import annotations

from arenyxa.logging.factory import get_logger


class LoggingBridge:
    """Small compatibility bridge for migrating modules to unified logging."""

    def __init__(self, name: str) -> None:
        self.logger = get_logger(name)

    def info(self, message: str, *args: object) -> None:
        self.logger.info(message, *args)

    def error(self, message: str, *args: object) -> None:
        self.logger.error(message, *args)
