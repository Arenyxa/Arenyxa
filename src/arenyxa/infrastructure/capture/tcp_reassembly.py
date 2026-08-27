from __future__ import annotations

from typing import Any
from dataclasses import field

from arenyxa.compat import dataclass


@dataclass(slots=True)
class TcpReassemblyUpdate:
    stream_bytes: bytes = b""
    contiguous_bytes: int = 0
    pending_bytes: int = 0
    retransmission: bool = False
    out_of_order: bool = False
    gap: bool = False
    truncated: bool = False
    closed: bool = False


@dataclass(slots=True)
class _TcpDirectionState:
    expected_sequence: int | None = None
    probe: bytearray = field(default_factory=bytearray)
    pending: dict[int, bytes] = field(default_factory=dict)
    pending_bytes: int = 0
    contiguous_bytes: int = 0
    last_seen: int = 0
    truncated: bool = False


class TcpReassemblyManager:
    """Bounded directional TCP stream reassembly for native application probing.

    The manager intentionally retains only a small prefix of each contiguous
    direction for protocol identification. It does not expose captured payload
    in logs or diagnostics and applies global/per-flow budgets so hostile or
    extremely long captures cannot grow memory without bound.
    """

    MAX_FLOWS = 4096
    MAX_PROBE_BYTES = 64 * 1024
    MAX_PENDING_SEGMENTS = 64
    MAX_PENDING_BYTES = 128 * 1024
    MAX_GLOBAL_BYTES = 64 * 1024 * 1024
    MAX_SEGMENT_BYTES = 1024 * 1024

    def __init__(self) -> None:
        self._states: dict[tuple[str, int, str, int], _TcpDirectionState] = {}
        self._clock = 0
        self._retained_bytes = 0

    @staticmethod
    def _sequence_delta(left: int, right: int) -> int:
        """Signed 32-bit delta ``left - right`` with wrap-around semantics."""
        return ((int(left) - int(right) + 0x80000000) & 0xFFFFFFFF) - 0x80000000

    def feed(
        self,
        key: tuple[str, int, str, int],
        *,
        sequence: int,
        payload: bytes,
        flags: set[str] | frozenset[str] | tuple[str, ...] = (),
    ) -> TcpReassemblyUpdate:
        self._clock += 1
        # P0 hardening: reject oversized TCP segments before expensive processing.
        if len(payload) > self.MAX_SEGMENT_BYTES:
            return TcpReassemblyUpdate(truncated=True)

        normalized_flags = {str(item).casefold() for item in flags}
        state = self._states.get(key)
        if state is None:
            self._ensure_flow_capacity()
            state = _TcpDirectionState(last_seen=self._clock)
            self._states[key] = state
        state.last_seen = self._clock

        data_sequence = (int(sequence) + int("syn" in normalized_flags)) & 0xFFFFFFFF
        update = TcpReassemblyUpdate()
        if state.expected_sequence is None:
            state.expected_sequence = data_sequence

        if payload:
            delta = self._sequence_delta(data_sequence, state.expected_sequence)
            if delta == 0:
                self._append_contiguous(state, payload)
                self._drain_pending(state)
            elif delta > 0:
                update.out_of_order = True
                update.gap = True
                self._store_pending(state, data_sequence, payload)
            else:
                overlap = -delta
                if overlap >= len(payload):
                    update.retransmission = True
                else:
                    update.retransmission = True
                    self._append_contiguous(state, payload[overlap:])
                    self._drain_pending(state)

        if "rst" in normalized_flags or "fin" in normalized_flags:
            update.closed = True

        update.stream_bytes = bytes(state.probe)
        update.contiguous_bytes = state.contiguous_bytes
        update.pending_bytes = state.pending_bytes
        update.truncated = state.truncated

        self._enforce_global_budget(exclude=key)
        if update.closed:
            self._drop_state(key)
        return update

    def reset(self) -> None:
        self._states.clear()
        self._retained_bytes = 0

    def _append_contiguous(self, state: _TcpDirectionState, payload: bytes) -> None:
        if not payload:
            return
        expected = state.expected_sequence
        if expected is None:
            return
        state.expected_sequence = (expected + len(payload)) & 0xFFFFFFFF
        state.contiguous_bytes += len(payload)
        remaining = self.MAX_PROBE_BYTES - len(state.probe)
        if remaining > 0:
            chunk = payload[:remaining]
            state.probe.extend(chunk)
            self._retained_bytes += len(chunk)
        if len(payload) > max(0, remaining):
            state.truncated = True

    def _store_pending(self, state: _TcpDirectionState, sequence: int, payload: bytes) -> None:
        existing = state.pending.get(sequence)
        if existing is not None and len(existing) >= len(payload):
            return
        if existing is not None:
            state.pending_bytes -= len(existing)
            self._retained_bytes -= len(existing)
        if len(state.pending) >= self.MAX_PENDING_SEGMENTS and sequence not in state.pending:
            state.truncated = True
            return
        available = self.MAX_PENDING_BYTES - state.pending_bytes
        if available <= 0:
            state.truncated = True
            return
        bounded = bytes(payload[:available])
        if not bounded:
            return
        state.pending[sequence] = bounded
        state.pending_bytes += len(bounded)
        self._retained_bytes += len(bounded)
        if len(bounded) < len(payload):
            state.truncated = True

    def _drain_pending(self, state: _TcpDirectionState) -> None:
        while state.pending and state.expected_sequence is not None:
            best_sequence: int | None = None
            best_delta: int | None = None
            for candidate in state.pending:
                delta = self._sequence_delta(candidate, state.expected_sequence)
                if delta <= 0 and (best_delta is None or delta > best_delta):
                    best_sequence = candidate
                    best_delta = delta
            if best_sequence is None:
                return
            segment = state.pending.pop(best_sequence)
            state.pending_bytes -= len(segment)
            self._retained_bytes -= len(segment)
            overlap = -int(best_delta or 0)
            if overlap < len(segment):
                self._append_contiguous(state, segment[overlap:])

    def _ensure_flow_capacity(self) -> None:
        if len(self._states) < self.MAX_FLOWS:
            return
        victim = min(self._states.items(), key=lambda item: item[1].last_seen)[0]
        self._drop_state(victim)

    def _enforce_global_budget(self, *, exclude: tuple[str, int, str, int]) -> None:
        while self._retained_bytes > self.MAX_GLOBAL_BYTES and self._states:
            candidates = [(key, state) for key, state in self._states.items() if key != exclude]
            if not candidates:
                state = self._states.get(exclude)
                if state is not None:
                    self._trim_state(state)
                return
            victim = min(candidates, key=lambda item: item[1].last_seen)[0]
            self._drop_state(victim)

    def _trim_state(self, state: _TcpDirectionState) -> None:
        for segment in state.pending.values():
            self._retained_bytes -= len(segment)
        state.pending.clear()
        state.pending_bytes = 0
        if len(state.probe) > self.MAX_PROBE_BYTES // 2:
            removed = len(state.probe) - self.MAX_PROBE_BYTES // 2
            del state.probe[self.MAX_PROBE_BYTES // 2:]
            self._retained_bytes -= removed
        state.truncated = True

    def _drop_state(self, key: tuple[str, int, str, int]) -> None:
        state = self._states.pop(key, None)
        if state is None:
            return
        self._retained_bytes -= len(state.probe) + state.pending_bytes
        if self._retained_bytes < 0:
            self._retained_bytes = 0

    @property
    def diagnostics(self) -> dict[str, Any]:
        return {
            "active_directions": len(self._states),
            "retained_bytes": self._retained_bytes,
            "max_flows": self.MAX_FLOWS,
            "max_probe_bytes_per_direction": self.MAX_PROBE_BYTES,
            "max_pending_bytes_per_direction": self.MAX_PENDING_BYTES,
            "max_global_bytes": self.MAX_GLOBAL_BYTES,
        }
