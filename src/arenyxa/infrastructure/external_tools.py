from __future__ import annotations

"""Versioned capability contracts for optional external executables.

External tools are never treated as "present == compatible".  Every integration can
request a bounded version probe and, for TShark, a field-schema contract before it is
allowed onto the data path.  Callers must explicitly degrade when ``usable`` is false.
"""

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.process_safety import validated_argv


@dataclass(frozen=True, slots=True)
class ExternalToolCapability:
    name: str
    executable: str
    available: bool
    compatible: bool
    version: str = ""
    detail: str = ""
    missing_capabilities: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        return self.available and self.compatible and not self.missing_capabilities

    def require(self, *, code: str, message: str, domain: str = "RUNTIME") -> "ExternalToolCapability":
        if self.usable:
            return self
        raise ArenyxaError(
            code,
            message,
            domain=domain,
            context={
                "tool": self.name,
                "executable": self.executable,
                "version": self.version,
                "detail": self.detail,
                "missing_capabilities": list(self.missing_capabilities),
            },
        )


class ExternalToolProbe:
    """Bounded executable probes with explicit compatibility contracts."""

    _VERSION = re.compile(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?")

    @classmethod
    def probe(
        cls,
        name: str,
        *,
        executable: str | None = None,
        version_args: Sequence[str] = ("--version",),
        minimum: tuple[int, int] | None = None,
        timeout: float = 2.0,
    ) -> ExternalToolCapability:
        resolved = cls._resolve(name, executable)
        if not resolved:
            return ExternalToolCapability(name, "", False, False, detail="executable not found")
        completed = cls._run_probe(resolved, version_args, timeout)
        if completed is None:
            return ExternalToolCapability(name, resolved, True, False, detail="bounded version probe failed")
        output = (completed.stdout or "").strip()
        first = output.splitlines()[0][:200] if output else ""
        match = cls._VERSION.search(output)
        if completed.returncode != 0 or match is None:
            return ExternalToolCapability(
                name,
                resolved,
                True,
                False,
                first,
                "version contract unavailable",
            )
        parsed = (int(match.group(1)), int(match.group(2)))
        compatible = minimum is None or parsed >= minimum
        return ExternalToolCapability(
            name,
            resolved,
            True,
            compatible,
            match.group(0),
            "compatible" if compatible else f"requires >= {minimum[0]}.{minimum[1]}",
        )

    @classmethod
    def tshark(
        cls,
        *,
        executable: str | None = None,
        required_fields: Sequence[str] = (),
        timeout: float = 5.0,
    ) -> ExternalToolCapability:
        base = cls.probe(
            "tshark",
            executable=executable,
            version_args=("-v",),
            minimum=(3, 0),
            timeout=min(timeout, 3.0),
        )
        if not base.available or not base.compatible or not required_fields:
            return base
        fields = cls._tshark_fields(base.executable, timeout=timeout)
        if fields is None:
            return ExternalToolCapability(
                base.name,
                base.executable,
                True,
                False,
                base.version,
                "field capability catalog probe failed",
                tuple(str(item) for item in required_fields),
            )
        missing = tuple(sorted({str(item) for item in required_fields if str(item) not in fields}))
        if missing:
            return ExternalToolCapability(
                base.name,
                base.executable,
                True,
                True,
                base.version,
                "required field contract is not satisfied",
                missing,
            )
        return base

    @classmethod
    def tshark_supported_fields(
        cls,
        *,
        executable: str | None = None,
        timeout: float = 10.0,
    ) -> frozenset[str]:
        base = cls.tshark(executable=executable)
        if not base.usable:
            return frozenset()
        fields = cls._tshark_fields(base.executable, timeout=timeout)
        return frozenset(fields or ())

    @classmethod
    def dumpcap(cls, *, executable: str | None = None) -> ExternalToolCapability:
        return cls.probe("dumpcap", executable=executable, version_args=("-v",), minimum=(3, 0))

    @classmethod
    def mitmdump(cls, *, executable: str | None = None) -> ExternalToolCapability:
        return cls.probe("mitmdump", executable=executable, minimum=(8, 0))

    @staticmethod
    def _resolve(name: str, executable: str | None) -> str:
        if executable:
            candidate = str(executable).strip()
            if not candidate:
                return ""
            # Explicit paths are preserved; command names are resolved without a shell.
            if any(separator in candidate for separator in ("/", "\\")):
                return candidate
            return str(shutil.which(candidate) or "")
        return str(shutil.which(name) or "")

    @staticmethod
    def _run_probe(executable: str, args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                validated_argv([executable, *[str(item) for item in args]]),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(0.25, float(timeout)),
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError, ValueError):
            return None

    @classmethod
    def _tshark_fields(cls, executable: str, *, timeout: float) -> set[str] | None:
        completed = cls._run_probe(executable, ("-G", "fields"), timeout)
        if completed is None or completed.returncode != 0:
            return None
        supported: set[str] = set()
        for line in (completed.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] == "F" and parts[2]:
                supported.add(parts[2])
        return supported or None
