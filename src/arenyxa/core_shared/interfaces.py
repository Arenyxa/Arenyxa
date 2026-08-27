from __future__ import annotations

from abc import ABC, abstractmethod


class ParserInterface(ABC):
    @abstractmethod
    def parse(self, data: bytes):
        """Parse one bounded byte sequence in a concrete parser implementation."""
        ...
