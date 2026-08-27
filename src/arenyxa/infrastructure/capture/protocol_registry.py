from __future__ import annotations

import logging
import threading
from dataclasses import asdict, field
from typing import Any, Callable, Iterable, Mapping

from arenyxa.compat import dataclass

LOGGER = logging.getLogger(__name__)

ProtocolDecoder = Callable[[bytes], Mapping[str, Any] | None]


@dataclass(frozen=True, slots=True)
class ProtocolField:
    """One discoverable protocol field exposed by the unified registry."""

    abbreviation: str
    name: str = ""
    field_type: str = ""
    protocol: str = ""
    description: str = ""
    source: str = "native"

    def snapshot(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProtocolRegistration:
    """Runtime registration for one protocol decoder or metadata provider.

    ``transports``/``ports``/``magic_hex`` are declarative, side-effect-free match
    hints. They let sandboxed protocol plugins participate in the live native decode
    path without importing plugin code or executing every decoder for every packet.
    """

    name: str
    description: str = ""
    source: str = "plugin"
    priority: int = 100
    fields: tuple[ProtocolField, ...] = field(default_factory=tuple)
    transports: tuple[str, ...] = field(default_factory=tuple)
    ports: tuple[int, ...] = field(default_factory=tuple)
    magic_hex: str = ""
    decoder: ProtocolDecoder | None = field(default=None, compare=False, repr=False)

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "protocol": self.name,
            "description": self.description,
            "source": self.source,
            "priority": self.priority,
            "fields": [item.snapshot() for item in self.fields],
            "transports": list(self.transports),
            "ports": list(self.ports),
            "magic_hex": self.magic_hex,
            "decoder": self.decoder is not None,
        }


class DynamicProtocolRegistry:
    """Thread-safe runtime registry used by native, plugin, and external dissectors.

    The registry deliberately keeps decoder invocation bounded: each protocol name owns
    at most one active registration per source and decode() stops at the first decoder
    that returns a mapping. External TShark metadata is imported as discoverable catalog
    entries only; arbitrary external code is never executed by this class.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._registrations: dict[str, list[ProtocolRegistration]] = {}
        self._fields: dict[str, ProtocolField] = {}

    @staticmethod
    def _normalize_name(value: str) -> str:
        name = str(value or "").strip().casefold()
        if not name or len(name) > 128:
            raise ValueError("protocol name must be 1..128 characters")
        if any(ord(ch) < 32 for ch in name):
            raise ValueError("protocol name contains control characters")
        return name

    def register(self, registration: ProtocolRegistration, *, replace: bool = False) -> None:
        name = self._normalize_name(registration.name)
        source = str(registration.source or "plugin").strip().casefold()[:64] or "plugin"
        transports = tuple(sorted({
            str(value).strip().casefold()
            for value in registration.transports
            if str(value).strip().casefold() in {"tcp", "udp", "sctp", "dccp"}
        }))
        ports = tuple(sorted({
            int(value) for value in registration.ports if 0 < int(value) <= 65535
        }))
        magic_hex = str(registration.magic_hex or "").strip().casefold()
        if magic_hex:
            if len(magic_hex) > 512 or len(magic_hex) % 2:
                raise ValueError("magic_hex must be an even-length hex string up to 256 bytes")
            try:
                bytes.fromhex(magic_hex)
            except ValueError as exc:
                raise ValueError("magic_hex is not valid hexadecimal") from exc
        normalized = ProtocolRegistration(
            name=name,
            description=str(registration.description or "")[:2048],
            source=source,
            priority=max(-10_000, min(10_000, int(registration.priority))),
            fields=tuple(registration.fields),
            transports=transports,
            ports=ports,
            magic_hex=magic_hex,
            decoder=registration.decoder,
        )
        with self._lock:
            rows = self._registrations.setdefault(name, [])
            index = next((i for i, item in enumerate(rows) if item.source == source), None)
            if index is not None:
                if not replace:
                    raise ValueError(f"protocol already registered from source {source}: {name}")
                rows[index] = normalized
            else:
                rows.append(normalized)
            rows.sort(key=lambda item: (item.priority, item.source))
            for field_item in normalized.fields:
                self._register_field_locked(field_item, replace=replace)

    def unregister(self, name: str, *, source: str | None = None) -> int:
        key = self._normalize_name(name)
        with self._lock:
            rows = self._registrations.get(key, [])
            source_key = None if source is None else str(source).strip().casefold()
            if source_key is None:
                removed = len(rows)
                self._registrations.pop(key, None)
            else:
                kept = [item for item in rows if item.source != source_key]
                removed = len(rows) - len(kept)
                if kept:
                    self._registrations[key] = kept
                else:
                    self._registrations.pop(key, None)
            stale_fields = [
                abbreviation for abbreviation, item in self._fields.items()
                if item.protocol == key and (source_key is None or item.source == source_key)
            ]
            for abbreviation in stale_fields:
                self._fields.pop(abbreviation, None)
            return removed

    def register_field(self, field_item: ProtocolField, *, replace: bool = False) -> None:
        with self._lock:
            self._register_field_locked(field_item, replace=replace)

    def _register_field_locked(self, field_item: ProtocolField, *, replace: bool) -> None:
        abbreviation = str(field_item.abbreviation or "").strip()
        if not abbreviation or len(abbreviation) > 256:
            raise ValueError("field abbreviation must be 1..256 characters")
        normalized = ProtocolField(
            abbreviation=abbreviation,
            name=str(field_item.name or "")[:512],
            field_type=str(field_item.field_type or "")[:128],
            protocol=str(field_item.protocol or "")[:128].casefold(),
            description=str(field_item.description or "")[:2048],
            source=str(field_item.source or "native")[:64].casefold(),
        )
        if abbreviation in self._fields and not replace:
            return
        self._fields[abbreviation] = normalized

    def get(self, name: str) -> tuple[ProtocolRegistration, ...]:
        key = self._normalize_name(name)
        with self._lock:
            return tuple(self._registrations.get(key, ()))

    def protocols(self, *, contains: str = "", limit: int = 5000) -> list[dict[str, Any]]:
        needle = str(contains or "").casefold().strip()
        bounded = max(1, min(50_000, int(limit)))
        with self._lock:
            rows = [item for group in self._registrations.values() for item in group]
        result: list[dict[str, Any]] = []
        for item in sorted(rows, key=lambda value: (value.name, value.priority, value.source)):
            snapshot = item.snapshot()
            if needle and needle not in " ".join(str(value) for value in snapshot.values()).casefold():
                continue
            result.append(snapshot)
            if len(result) >= bounded:
                break
        return result

    def fields(self, *, contains: str = "", protocol: str = "", limit: int = 5000) -> list[dict[str, str]]:
        needle = str(contains or "").casefold().strip()
        protocol_key = str(protocol or "").casefold().strip()
        bounded = max(1, min(100_000, int(limit)))
        with self._lock:
            rows = tuple(self._fields.values())
        result: list[dict[str, str]] = []
        for item in sorted(rows, key=lambda value: value.abbreviation):
            if protocol_key and item.protocol != protocol_key:
                continue
            snapshot = item.snapshot()
            if needle and needle not in " ".join(snapshot.values()).casefold():
                continue
            result.append(snapshot)
            if len(result) >= bounded:
                break
        return result

    def decode(self, protocol: str, payload: bytes | bytearray | memoryview) -> dict[str, Any] | None:
        raw = bytes(payload)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("protocol decode payload exceeds 16 MiB safety budget")
        for registration in self.get(protocol):
            if registration.decoder is None:
                continue
            try:
                decoded = registration.decoder(raw)
            except (KeyError, TypeError, ValueError, OSError, RuntimeError):
                LOGGER.exception("Protocol plugin decoder failed: protocol=%s source=%s", protocol, registration.source)
                continue
            if decoded is not None:
                return dict(decoded)
        return None

    @staticmethod
    def _matches(
        registration: ProtocolRegistration,
        *,
        transport: str,
        source_port: int,
        destination_port: int,
        payload: bytes,
    ) -> bool:
        if registration.decoder is None:
            return False
        transport_key = str(transport or "").strip().casefold()
        if registration.transports and transport_key not in registration.transports:
            return False
        if registration.ports and source_port not in registration.ports and destination_port not in registration.ports:
            return False
        if registration.magic_hex:
            try:
                prefix = bytes.fromhex(registration.magic_hex)
            except ValueError:
                return False
            if not payload.startswith(prefix):
                return False
        # A decoder with no matcher remains manually addressable via decode(name, payload),
        # but is never sprayed across the packet hot path.
        return bool(registration.transports or registration.ports or registration.magic_hex)

    def decode_matching(
        self,
        payload: bytes | bytearray | memoryview,
        *,
        transport: str,
        source_port: int,
        destination_port: int,
    ) -> tuple[str, dict[str, Any], str] | None:
        """Decode with the highest-priority runtime registration matching flow hints."""
        raw = bytes(payload)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("protocol decode payload exceeds 16 MiB safety budget")
        with self._lock:
            candidates = [
                item
                for rows in self._registrations.values()
                for item in rows
                if self._matches(
                    item,
                    transport=transport,
                    source_port=int(source_port),
                    destination_port=int(destination_port),
                    payload=raw,
                )
            ]
        candidates.sort(key=lambda item: (item.priority, item.name, item.source))
        for registration in candidates:
            try:
                decoded = registration.decoder(raw) if registration.decoder is not None else None
            except (KeyError, TypeError, ValueError, OSError, RuntimeError):
                LOGGER.exception(
                    "Protocol plugin decoder failed on matched flow: protocol=%s source=%s",
                    registration.name,
                    registration.source,
                )
                continue
            if decoded is not None:
                return registration.name, dict(decoded), registration.source
        return None

    def import_native_catalog(self, rows: Iterable[Mapping[str, Any]]) -> int:
        imported = 0
        for row in rows:
            name = str(row.get("protocol") or row.get("name") or "").strip()
            if not name:
                continue
            try:
                self.register(
                    ProtocolRegistration(
                        name=name,
                        description=str(row.get("description") or row.get("mode") or "Arenyxa native protocol"),
                        source="native",
                        priority=0,
                    ),
                    replace=True,
                )
            except ValueError:
                continue
            imported += 1
        return imported

    def import_external_catalog(
        self,
        protocols: Iterable[Mapping[str, Any]],
        fields: Iterable[Mapping[str, Any]],
        *,
        source: str = "tshark",
    ) -> dict[str, int]:
        protocol_count = 0
        field_count = 0
        source_key = str(source or "external").casefold()
        for row in protocols:
            name = str(row.get("filter_name") or row.get("short_name") or row.get("name") or "").strip()
            if not name:
                continue
            try:
                self.register(
                    ProtocolRegistration(
                        name=name,
                        description=str(row.get("name") or row.get("short_name") or "external dissector"),
                        source=source_key,
                        priority=1000,
                    ),
                    replace=True,
                )
            except ValueError:
                continue
            protocol_count += 1
        for row in fields:
            abbreviation = str(row.get("abbreviation") or "").strip()
            if not abbreviation:
                continue
            try:
                self.register_field(
                    ProtocolField(
                        abbreviation=abbreviation,
                        name=str(row.get("name") or ""),
                        field_type=str(row.get("type") or ""),
                        protocol=str(row.get("protocol") or ""),
                        description=str(row.get("description") or ""),
                        source=source_key,
                    ),
                    replace=True,
                )
            except ValueError:
                continue
            field_count += 1
        return {"protocols": protocol_count, "fields": field_count}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            protocol_names = len(self._registrations)
            registration_count = sum(len(rows) for rows in self._registrations.values())
            field_count = len(self._fields)
            protocol_sources = {item.source for rows in self._registrations.values() for item in rows}
            field_sources = {item.source for item in self._fields.values()}
        return {
            "protocol_names": protocol_names,
            "registrations": registration_count,
            "fields": field_count,
            "sources": sorted(protocol_sources | field_sources),
            "protocol_sources": sorted(protocol_sources),
            "field_sources": sorted(field_sources),
        }


_GLOBAL_PROTOCOL_REGISTRY = DynamicProtocolRegistry()


def global_protocol_registry() -> DynamicProtocolRegistry:
    return _GLOBAL_PROTOCOL_REGISTRY
