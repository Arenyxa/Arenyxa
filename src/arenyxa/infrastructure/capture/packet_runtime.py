from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Sequence

from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.process_safety import validated_argv
from arenyxa.infrastructure.external_tools import ExternalToolProbe

if TYPE_CHECKING:
    from arenyxa.infrastructure.capture.packet_models import PacketExecutionProfile


class PacketRuntimeMixin:
    """External packet-runtime bridge, statistics taps, and capture-file transforms."""

    def interfaces(self) -> list[str]:
        """List capture interfaces exposed by the packet runtime."""
        if not self.available:
            return []
        output = self._run_tshark(["-D"], timeout=20)
        return [line.strip() for line in output.splitlines() if line.strip()]

    def glossary(self, kind: str) -> list[str]:
        """Return packet-analysis terminology and capability guidance."""
        allowed = {"protocols", "fields", "values", "folders", "heuristic-decodes", "currentprefs", "defaultprefs"}
        if kind not in allowed:
            raise ValueError(f"unsupported glossary: {kind}")
        output = self._run_tshark(["-G", kind], timeout=45)
        return [line for line in output.splitlines() if line.strip()]

    def protocol_catalog(self) -> list[dict[str, str]]:
        """Return the dynamically discovered protocol catalog."""
        result: list[dict[str, str]] = []
        for line in self.glossary("protocols"):
            parts = line.split("\t")
            if len(parts) >= 3:
                result.append({"name": parts[0], "short_name": parts[1], "filter_name": parts[2]})
        return result

    def field_catalog(self, limit: int | None = None) -> list[dict[str, str]]:
        """Return the dynamically discovered dissector field catalog."""
        result: list[dict[str, str]] = []
        for line in self.glossary("fields"):
            parts = line.split("\t")
            if len(parts) >= 7 and parts[0] == "F":
                result.append({
                    "name": parts[1],
                    "abbreviation": parts[2],
                    "type": parts[3],
                    "protocol": parts[4],
                    "base": parts[5],
                    "description": parts[6],
                })
                if limit is not None and len(result) >= max(0, int(limit)):
                    break
        return result

    def object_exporters(self) -> list[str]:
        """List object-export capabilities advertised by the runtime."""
        if not self.available:
            return []
        completed = self._run_process([self.executable, "--export-objects", "help"], timeout=20, check=False)
        text = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        names: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            match = re.match(r"^([A-Za-z0-9_.+-]+)\s", stripped)
            if match:
                names.append(match.group(1))
        return sorted(set(names))

    def capture_formats(self) -> list[str]:
        """List supported capture file formats and metadata."""
        if not self.available:
            return []
        completed = self._run_process([self.executable, "-F"], timeout=20, check=False)
        text = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        result: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.casefold().startswith("tshark"):
                continue
            token = stripped.split()[0].strip()
            if re.fullmatch(r"[A-Za-z0-9_.+-]+", token):
                result.append(token)
        return sorted(set(result))

    def list_data_link_types(self, interface: str) -> list[str]:
        """List data-link types supported by a capture format."""
        output = self._run_tshark(["-i", str(interface), "-L"], timeout=20)
        return [line.strip() for line in output.splitlines() if line.strip()]

    def validate_display_filter(self, capture: Path | str, expression: str) -> tuple[bool, str]:
        """Validate a packet display filter without executing a capture."""
        if not self.available:
            self._capture_path(capture)
            return (not bool(str(expression).strip()), "native fallback supports an empty display filter only")
        path = self._capture_path(capture)
        completed = self._run_process(
            [self.executable, "-n", "-r", str(path), "-c", "1", "-Y", str(expression), "-T", "fields", "-e", "frame.number"],
            timeout=30,
            check=False,
        )
        return completed.returncode == 0, (completed.stderr or "").strip()

    def protocol_hierarchy(self, capture: Path | str, display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        """Compute protocol hierarchy statistics for a capture."""
        if not self.available:
            return self._native_stat_text(capture, "protocol_hierarchy", display_filter)
        return self._tap(capture, self._tap_filter("io,phs", display_filter), profile)

    def conversations(self, capture: Path | str, types: Sequence[str] = ("eth", "ip", "ipv6", "tcp", "udp"), display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        """Return bounded conversation statistics for a capture."""
        if not self.available:
            return self._native_stat_text(capture, "conversations", display_filter)
        taps = [self._tap_filter(f"conv,{kind}", display_filter) for kind in types if kind in self.CONVERSATION_TYPES]
        return self._taps(capture, taps, profile)

    def endpoints(self, capture: Path | str, types: Sequence[str] = ("eth", "ip", "ipv6", "tcp", "udp"), display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        """Return bounded endpoint statistics for a capture."""
        if not self.available:
            return self._native_stat_text(capture, "endpoints", display_filter)
        taps = [self._tap_filter(f"endpoints,{kind}", display_filter) for kind in types if kind in self.CONVERSATION_TYPES]
        return self._taps(capture, taps, profile)

    def expert_information(self, capture: Path | str, display_filter: str = "", minimum: str = "note", profile: PacketExecutionProfile | None = None) -> str:
        """Return expert diagnostics emitted by packet analysis."""
        if not self.available:
            return self._native_stat_text(capture, "expert", display_filter)
        levels = {"error", "warn", "note", "chat", "comment"}
        level = minimum if minimum in levels else "note"
        tap = f"expert,{level}"
        if display_filter:
            tap = f"{tap},{display_filter}"
        return self._tap(capture, tap, profile)

    def io_statistics(self, capture: Path | str, interval: float = 1.0, filters: Sequence[str] = (), profile: PacketExecutionProfile | None = None) -> str:
        """Return time-bucketed packet and byte statistics."""
        if not self.available:
            display_filter = next((str(item).strip() for item in filters if str(item).strip()), "")
            return self._native_stat_text(capture, "io_graph", display_filter)
        value = max(0.000001, float(interval))
        tap = f"io,stat,{value:g}"
        for expression in filters:
            if str(expression).strip():
                tap += f",{expression}"
        return self._tap(capture, tap, profile)

    def packet_length_statistics(self, capture: Path | str, display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        """Return packet-length distribution statistics."""
        if not self.available:
            return self._native_stat_text(capture, "packet_lengths", display_filter)
        return self._tap(capture, self._tap_filter("plen,tree", display_filter), profile)

    def flow_graph(self, capture: Path | str, protocol: str = "tcp", address_mode: str = "network", display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        """Build a bounded packet flow graph from a capture."""
        if not self.available:
            return self._native_stat_text(capture, "flow_graph", display_filter)
        protocol_value = protocol if protocol in {"any", "icmp", "icmpv6", "lbm_uim", "tcp"} else "tcp"
        address_value = address_mode if address_mode in {"standard", "network"} else "network"
        return self._tap(capture, self._tap_filter(f"flow,{protocol_value},{address_value}", display_filter), profile)

    def service_statistics(self, capture: Path | str, display_filter: str = "", profile: PacketExecutionProfile | None = None) -> str:
        """Return application-service statistics for a capture."""
        if not self.available:
            return self._native_stat_text(capture, "service_statistics", display_filter)
        taps = [
            self._tap_filter("dns,tree", display_filter),
            self._tap_filter("http,stat", display_filter),
            self._tap_filter("http,tree", display_filter),
            self._tap_filter("http_req,tree", display_filter),
            self._tap_filter("http_srv,tree", display_filter),
            self._tap_filter("http2,tree", display_filter),
            self._tap_filter("icmp,srt", display_filter),
            self._tap_filter("icmpv6,srt", display_filter),
        ]
        return self._taps(capture, taps, profile)

    def rtp_streams(self, capture: Path | str, profile: PacketExecutionProfile | None = None) -> str:
        """Return detected real-time media stream statistics."""
        if not self.available:
            return self._native_stat_text(capture, "rtp_streams", "")
        return self._tap(capture, "rtp,streams", profile)

    def statistics_tap(self, capture: Path | str, tap: str, profile: PacketExecutionProfile | None = None) -> str:
        """Execute one validated statistics tap."""
        value = str(tap).strip()
        if not value or any(character in value for character in "\r\n"):
            raise ValueError("invalid statistics tap")
        return self._tap(capture, value, profile)

    def statistics_taps(self, capture: Path | str, taps: Sequence[str], profile: PacketExecutionProfile | None = None) -> str:
        """List statistics taps available in the packet runtime."""
        values = [str(tap).strip() for tap in taps if str(tap).strip()]
        if not values or any(any(character in value for character in "\r\n") for value in values):
            raise ValueError("invalid statistics taps")
        return self._taps(capture, values, profile)

    def follow_stream(
        self,
        capture: Path | str,
        protocol: str,
        stream_filter: str | int,
        mode: str = "utf-8",
        range_spec: str = "",
        profile: PacketExecutionProfile | None = None,
    ) -> str:
        """Follow and decode one bounded transport or application stream."""
        protocol_value = str(protocol).casefold()
        mode_value = str(mode).casefold()
        if protocol_value not in self.FOLLOW_PROTOCOLS:
            raise ValueError(f"unsupported follow protocol: {protocol}")
        if mode_value not in self.FOLLOW_MODES:
            raise ValueError(f"unsupported follow mode: {mode}")
        stream_value = str(stream_filter).strip()
        if not stream_value or any(character in stream_value for character in "\r\n"):
            raise ValueError("invalid stream filter")
        tap = f"follow,{protocol_value},{mode_value},{stream_value}"
        if range_spec:
            range_value = str(range_spec).strip()
            if any(character in range_value for character in "\r\n"):
                raise ValueError("invalid stream range")
            tap += f",{range_value}"
        return self._tap(capture, tap, profile)

    def export_filtered_capture(
        self,
        capture: Path | str,
        destination: Path | str,
        display_filter: str = "",
        output_format: str = "pcapng",
        profile: PacketExecutionProfile | None = None,
    ) -> Path:
        """Export packets matching a validated display filter."""
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        args = self._base_read_args(source, profile)
        if display_filter:
            args.extend(["-Y", display_filter])
        args.extend(["-F", str(output_format), "-w", str(target)])
        self._run_tshark(args, timeout=max(self.timeout_seconds, 300.0))
        if not target.exists():
            raise ArenyxaError("PACKET_ANALYSIS_EXPORT_FAILED", "Packet-analysis runtime did not create the requested capture file.", domain="CAPTURE")
        return target

    def export_dissections(
        self,
        capture: Path | str,
        destination: Path | str,
        output_format: str = "json",
        display_filter: str = "",
        profile: PacketExecutionProfile | None = None,
        include_raw: bool = False,
    ) -> Path:
        """Export structured packet dissections in a bounded format."""
        if output_format not in self.OUTPUT_FORMATS:
            raise ValueError(f"unsupported output format: {output_format}")
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        args = self._base_read_args(source, profile)
        args.extend(["-T", output_format])
        if include_raw and output_format in {"ek", "json", "jsonraw", "text"}:
            args.append("-x")
        if display_filter:
            args.extend(["-Y", display_filter])
        completed = self._run_process([self.executable, *args], timeout=max(self.timeout_seconds, 300.0), check=True)
        target.write_text(completed.stdout or "", encoding="utf-8")
        return target

    def export_objects(self, capture: Path | str, protocol: str, destination: Path | str, profile: PacketExecutionProfile | None = None) -> list[Path]:
        """Export application objects using a supported extractor."""
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.mkdir(parents=True, exist_ok=True)
        before = {path.name for path in target.iterdir() if path.is_file()}
        args = self._base_read_args(source, profile)
        args.extend(["--export-objects", f"{str(protocol).strip()},{target}"])
        self._run_tshark(args, timeout=max(self.timeout_seconds, 300.0))
        return sorted((path for path in target.iterdir() if path.is_file() and path.name not in before), key=lambda item: item.name.casefold())

    def merge_captures(self, captures: Sequence[Path | str], destination: Path | str, chronological: bool = True) -> Path:
        """Merge multiple capture files into one ordered capture."""
        executable = shutil.which("mergecap")
        if not executable:
            raise ArenyxaError("PACKET_ANALYSIS_MERGECAP_MISSING", "mergecap is required for capture merging.", domain="CAPTURE")
        sources = [self._capture_path(item) for item in captures]
        if len(sources) < 2:
            raise ValueError("at least two capture files are required")
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        args = [executable, "-w", str(target)]
        if not chronological:
            args.append("-a")
        args.extend(str(item) for item in sources)
        self._run_process(args, timeout=300, check=True)
        return target

    def convert_capture(self, capture: Path | str, destination: Path | str, output_format: str = "pcapng") -> Path:
        """Convert a capture file to a supported target format."""
        executable = shutil.which("editcap")
        if not executable:
            return self.export_filtered_capture(capture, destination, output_format=output_format)
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        self._run_process([executable, "-F", str(output_format), str(source), str(target)], timeout=300, check=True)
        return target

    def reorder_capture(self, capture: Path | str, destination: Path | str) -> Path:
        """Rewrite a capture in timestamp order."""
        executable = shutil.which("reordercap")
        if not executable:
            raise ArenyxaError("PACKET_ANALYSIS_REORDERCAP_MISSING", "reordercap is required for timestamp reordering.", domain="CAPTURE")
        source = self._capture_path(capture)
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        self._run_process([executable, str(source), str(target)], timeout=300, check=True)
        return target

    def _base_read_args(self, path: Path, profile: PacketExecutionProfile | None) -> list[str]:
        args = ["-2", "-n", "-r", str(path)]
        if profile is None:
            return args
        if profile.configuration_profile:
            args.extend(["-C", profile.configuration_profile])
        if profile.name_resolution:
            args.extend(["-N", profile.name_resolution])
        for decode in profile.decode_as:
            value = str(decode).strip()
            if value:
                args.extend(["-d", value])
        for key, value in profile.preferences.items():
            if str(key).strip():
                args.extend(["-o", f"{key}:{value}"])
        if profile.keytab:
            args.extend(["-K", str(Path(profile.keytab).expanduser().resolve())])
        if profile.tls_keylog:
            args.extend(["-o", f"tls.keylog_file:{Path(profile.tls_keylog).expanduser().resolve()}"])
        if profile.enabled_protocols:
            args.extend(["--enable-protocol", ",".join(profile.enabled_protocols)])
        if profile.disabled_protocols:
            args.extend(["--disable-protocol", ",".join(profile.disabled_protocols)])
        for name in profile.enabled_heuristics:
            args.extend(["--enable-heuristic", str(name)])
        for name in profile.disabled_heuristics:
            args.extend(["--disable-heuristic", str(name)])
        return args

    def _tap(self, capture: Path | str, tap: str, profile: PacketExecutionProfile | None) -> str:
        return self._taps(capture, [tap], profile)

    def _taps(self, capture: Path | str, taps: Iterable[str], profile: PacketExecutionProfile | None) -> str:
        path = self._capture_path(capture)
        args = self._base_read_args(path, profile)
        args.insert(0, "-q")
        for tap in taps:
            if str(tap).strip():
                args.extend(["-z", str(tap)])
        return self._run_tshark(args, timeout=max(self.timeout_seconds, 180.0))

    @staticmethod
    def _tap_filter(base: str, display_filter: str) -> str:
        return f"{base},{display_filter}" if display_filter else base

    def _supported_fields(self) -> set[str]:
        if self._supported_field_cache is not None:
            return self._supported_field_cache
        supported: set[str] = set()
        for line in self.glossary("fields"):
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] == "F":
                supported.add(parts[2])
        self._supported_field_cache = supported
        return supported

    def _require_tshark_contract(self) -> None:
        capability = ExternalToolProbe.tshark(
            executable=self.executable or None,
            required_fields=("frame.number", "frame.time_epoch", "frame.len", "frame.protocols"),
        )
        if capability.usable:
            self.executable = capability.executable
            return
        setattr(self, "_external_runtime_failed", True)
        raise ArenyxaError(
            "PACKET_ANALYSIS_RUNTIME_INCOMPATIBLE",
            "The packet-analysis runtime does not satisfy Arenyxa's version/field contract.",
            domain="CAPTURE",
            context={
                "version": capability.version,
                "detail": capability.detail,
                "missing_fields": list(capability.missing_capabilities),
            },
        )

    def _run_tshark(self, args: Sequence[str], timeout: float | None = None) -> str:
        if not self.available:
            raise ArenyxaError(
                "PACKET_ANALYSIS_TSHARK_MISSING",
                "packet-analysis runtime is required for packet intelligence.",
                domain="CAPTURE",
                suggested_action="Install a compatible packet-analysis runtime and packet-capture driver, then restart Arenyxa.",
            )
        self._require_tshark_contract()
        try:
            completed = self._run_process([self.executable, *[str(item) for item in args]], timeout=timeout, check=True)
        except ArenyxaError:
            setattr(self, "_external_runtime_failed", True)
            raise
        return completed.stdout or ""

    def _iter_tshark_lines(self, args: Sequence[str], *, timeout: float) -> Iterable[str]:
        if not self.available:
            raise ArenyxaError(
                "PACKET_ANALYSIS_TSHARK_MISSING",
                "packet-analysis runtime is required for packet intelligence.",
                domain="CAPTURE",
                suggested_action="Install a compatible packet-analysis runtime and packet-capture driver, then restart Arenyxa.",
            )
        self._require_tshark_contract()
        command = [self.executable, *[str(item) for item in args]]
        stderr_file = tempfile.TemporaryFile(mode="w+b")
        process: subprocess.Popen[str] | None = None
        timer: threading.Timer | None = None
        timed_out = threading.Event()
        try:
            process = subprocess.Popen(
                validated_argv(command),
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )

            def expire() -> None:
                """Expire stale cached packet-runtime metadata."""
                if process is not None and process.poll() is None:
                    timed_out.set()
                    try:
                        process.kill()
                    except OSError:
                        record_current_exception(__name__, 'PacketRuntimeMixin._iter_tshark_lines.expire:452')

            timer = threading.Timer(max(1.0, float(timeout)), expire)
            timer.daemon = True
            timer.start()
            if process.stdout is None:
                raise ArenyxaError("PACKET_ANALYSIS_EXECUTION_FAILED", "packet-analysis stdout pipe was not created.", domain="CAPTURE")
            for raw_line in process.stdout:
                yield raw_line.rstrip("\r\n")
            return_code = process.wait()
            if timed_out.is_set():
                setattr(self, "_external_runtime_failed", True)
                raise ArenyxaError(
                    "PACKET_ANALYSIS_TIMEOUT",
                    "Packet analysis exceeded the configured execution deadline.",
                    domain="CAPTURE",
                    context={"command": Path(self.executable).name},
                )
            if return_code != 0:
                stderr_file.seek(0)
                stderr = stderr_file.read(16_384).decode("utf-8", errors="replace").strip()
                setattr(self, "_external_runtime_failed", True)
                raise ArenyxaError(
                    "PACKET_ANALYSIS_COMMAND_FAILED",
                    stderr[-3000:] or f"Packet-analysis command failed with exit code {return_code}.",
                    domain="CAPTURE",
                    context={"command": Path(self.executable).name, "returncode": return_code},
                )
        except OSError as exc:
            setattr(self, "_external_runtime_failed", True)
            raise ArenyxaError(
                "PACKET_ANALYSIS_EXECUTION_FAILED",
                "packet-analysis tooling could not be started.",
                domain="CAPTURE",
                context={"command": Path(self.executable).name, "error": str(exc)},
            ) from exc
        finally:
            if timer is not None:
                timer.cancel()
            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()
                if process.poll() is None:
                    try:
                        process.terminate()
                        process.wait(timeout=2.0)
                    except (OSError, subprocess.TimeoutExpired):
                        try:
                            process.kill()
                        except OSError:
                            record_current_exception(__name__, 'PacketRuntimeMixin._iter_tshark_lines:502')
            stderr_file.close()

    def _run_process(self, args: Sequence[str], timeout: float | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                validated_argv(list(args)),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.timeout_seconds,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except subprocess.TimeoutExpired as exc:
            raise ArenyxaError(
                "PACKET_ANALYSIS_TIMEOUT",
                "Packet analysis exceeded the configured execution deadline.",
                domain="CAPTURE",
                context={"command": Path(str(args[0])).name},
            ) from exc
        except OSError as exc:
            raise ArenyxaError(
                "PACKET_ANALYSIS_EXECUTION_FAILED",
                "packet-analysis tooling could not be started.",
                domain="CAPTURE",
                context={"command": Path(str(args[0])).name, "error": str(exc)},
            ) from exc
        if check and completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            raise ArenyxaError(
                "PACKET_ANALYSIS_COMMAND_FAILED",
                stderr[-3000:] or f"Packet-analysis command failed with exit code {completed.returncode}.",
                domain="CAPTURE",
                context={"command": Path(str(args[0])).name, "returncode": completed.returncode},
            )
        return completed

    @staticmethod
    def _capture_path(capture: Path | str) -> Path:
        path = Path(capture).expanduser().resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(path)
        return path
