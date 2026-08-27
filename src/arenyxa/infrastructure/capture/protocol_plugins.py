from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from collections.abc import Callable
from typing import Any

from arenyxa.infrastructure.atomic_io import read_text_limited
from arenyxa.infrastructure.capture.protocol_registry import (
    DynamicProtocolRegistry,
    ProtocolField,
    ProtocolRegistration,
)
from arenyxa.infrastructure.plugins import PluginManager, PluginSandbox, SandboxBudget

LOGGER = logging.getLogger(__name__)

_DESCRIPTOR_MAX_BYTES = 1024 * 1024
_PLUGIN_PAYLOAD_MAX_BYTES = 1024 * 1024


class ProtocolPluginLoader:
    """Load sandboxed protocol dissectors declared by installed Arenyxa plugins.

    A protocol plugin must advertise the ``protocol.dissector`` capability and provide
    ``protocols.json`` beside plugin.json. Decoding still happens in PluginSandbox;
    no plugin Python is imported into the desktop process.
    """

    def __init__(
        self,
        manager: PluginManager,
        sandbox: PluginSandbox,
        registry: DynamicProtocolRegistry,
    ) -> None:
        self.manager = manager
        self.sandbox = sandbox
        self.registry = registry

    def load(self) -> dict[str, Any]:
        loaded: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        for manifest, plugin_dir in self.manager.discover():
            if "protocol.dissector" not in {str(value).casefold() for value in manifest.capabilities}:
                continue
            active_permissions = {
                name for name, declaration in manifest.permissions.items()
                if declaration is not False and declaration is not None
            }
            if active_permissions:
                # Protocol decode is intentionally side-effect free. Plugins needing network,
                # storage, process, browser, clipboard, or database permissions cannot sit on
                # the capture hot path.
                skipped.append({"plugin_id": manifest.id, "reason": "protocol dissectors must be permission-free"})
                continue
            descriptor_path = plugin_dir / "protocols.json"
            try:
                descriptor = self._load_descriptor(descriptor_path)
                count = self._register_descriptor(manifest.id, plugin_dir, descriptor)
            except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
                LOGGER.warning("Protocol plugin descriptor rejected: %s: %s", manifest.id, exc)
                skipped.append({"plugin_id": manifest.id, "reason": f"{type(exc).__name__}: {exc}"})
                continue
            loaded.append({"plugin_id": manifest.id, "protocols": count})
        return {
            "loaded_plugins": len(loaded),
            "loaded": loaded,
            "skipped": skipped,
        }

    @staticmethod
    def _load_descriptor(path: Path) -> dict[str, Any]:
        raw = read_text_limited(path, _DESCRIPTOR_MAX_BYTES, encoding="utf-8")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("protocols.json root must be an object")
        if value.get("schema") not in {None, "arenyxa.protocol-plugin/v1"}:
            raise ValueError("unsupported protocol plugin descriptor schema")
        protocols = value.get("protocols")
        if not isinstance(protocols, list) or len(protocols) > 256:
            raise ValueError("protocols must be a list with at most 256 entries")
        return value

    def _register_descriptor(self, plugin_id: str, plugin_dir: Path, descriptor: dict[str, Any]) -> int:
        count = 0
        for raw in descriptor.get("protocols", []):
            if not isinstance(raw, dict):
                raise ValueError("protocol descriptor entries must be objects")
            name = str(raw.get("name") or "").strip().casefold()
            if not name:
                raise ValueError("protocol descriptor is missing name")
            fields: list[ProtocolField] = []
            raw_fields = raw.get("fields", [])
            if raw_fields is not None and not isinstance(raw_fields, list):
                raise ValueError("protocol fields must be a list")
            for field_raw in raw_fields or []:
                if not isinstance(field_raw, dict):
                    raise ValueError("protocol field descriptor must be an object")
                abbreviation = str(field_raw.get("abbreviation") or "").strip()
                if not abbreviation:
                    raise ValueError("protocol field abbreviation is required")
                fields.append(ProtocolField(
                    abbreviation=abbreviation,
                    name=str(field_raw.get("name") or ""),
                    field_type=str(field_raw.get("type") or ""),
                    protocol=name,
                    description=str(field_raw.get("description") or ""),
                    source=f"plugin:{plugin_id}",
                ))
            decoder = self._decoder(plugin_id, plugin_dir, name)
            raw_transports = raw.get("transports", raw.get("transport", []))
            if isinstance(raw_transports, str):
                raw_transports = [raw_transports]
            if raw_transports is None:
                raw_transports = []
            if not isinstance(raw_transports, list) or len(raw_transports) > 8:
                raise ValueError("protocol transports must be a list with at most 8 entries")
            transports = tuple(str(value).strip().casefold() for value in raw_transports if str(value).strip())
            if any(value not in {"tcp", "udp", "sctp", "dccp"} for value in transports):
                raise ValueError("unsupported protocol transport matcher")
            raw_ports = raw.get("ports", [])
            if raw_ports is None:
                raw_ports = []
            if not isinstance(raw_ports, list) or len(raw_ports) > 128:
                raise ValueError("protocol ports must be a list with at most 128 entries")
            ports = tuple(int(value) for value in raw_ports)
            if any(value <= 0 or value > 65535 for value in ports):
                raise ValueError("protocol ports must be within 1..65535")
            magic_hex = str(raw.get("magic_hex") or "").strip().casefold()
            self.registry.register(
                ProtocolRegistration(
                    name=name,
                    description=str(raw.get("description") or f"Arenyxa plugin protocol {name}"),
                    source=f"plugin:{plugin_id}",
                    priority=max(-1000, min(1000, int(raw.get("priority", 100)))),
                    fields=tuple(fields),
                    transports=transports,
                    ports=ports,
                    magic_hex=magic_hex,
                    decoder=decoder,
                ),
                replace=True,
            )
            count += 1
        return count

    def _decoder(self, plugin_id: str, plugin_dir: Path, protocol: str) -> Callable[[bytes], dict[str, Any] | None]:
        def decode(payload: bytes) -> dict[str, Any] | None:
            if len(payload) > _PLUGIN_PAYLOAD_MAX_BYTES:
                raise ValueError("plugin protocol payload exceeds 1 MiB safety budget")
            response = self.sandbox.invoke(
                plugin_dir,
                {
                    "operation": "protocol.decode",
                    "protocol": protocol,
                    "payload_b64": base64.b64encode(payload).decode("ascii"),
                },
                {},
                SandboxBudget(
                    timeout_seconds=5.0,
                    max_output_bytes=2 * 1024 * 1024,
                    max_memory_mb=256,
                    max_input_bytes=2 * 1024 * 1024,
                    max_processes=1,
                ),
            )
            if not isinstance(response, dict):
                raise ValueError(f"protocol plugin {plugin_id} returned a non-object response")
            if response.get("handled") is False:
                return None
            decoded = response.get("decoded", response)
            if not isinstance(decoded, dict):
                raise ValueError(f"protocol plugin {plugin_id} decoded payload is not an object")
            return dict(decoded)
        return decode
