from __future__ import annotations

import socket

import pytest

from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard


def test_network_guard_bounds_dns_fanout_before_connection_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (f"203.0.113.{index}", 0))
        for index in range(1, 101)
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: rows)
    guard = NetworkUseGuard(NetworkGuardPolicy(max_resolved_addresses=8))

    with guard.connection_candidates("many-addresses.example") as candidates:
        assert len(candidates) == 8
        assert candidates[0] == "203.0.113.1"
        assert candidates[-1] == "203.0.113.8"
    assert guard.snapshot()["max_resolved_addresses"] == 8


@pytest.mark.parametrize("value", [0, 257])
def test_network_guard_rejects_unbounded_dns_candidate_policy(value: int) -> None:
    with pytest.raises(ValueError, match="max_resolved_addresses"):
        NetworkUseGuard(NetworkGuardPolicy(max_resolved_addresses=value))
