from arenyxa.infrastructure.capture.tcp_reassembly import TcpReassemblyManager


def fuzz(data: bytes):
    raw = bytes(data)
    manager = TcpReassemblyManager()
    key = ("192.0.2.1", 40000, "198.51.100.2", 443)
    sequence = int.from_bytes((raw[:4] + b"\x00\x00\x00\x00")[:4], "big")
    cursor = 4
    # Exercise in-order, overlapping, retransmitted and out-of-order paths while
    # remaining under per-segment safety budgets.
    for index in range(0, min(len(raw) - cursor, 4096), 64):
        segment = raw[cursor + index: cursor + index + 64]
        if not segment:
            break
        delta = ((segment[0] if segment else 0) % 17) - 8
        flags = {"syn"} if index == 0 and (raw[0] if raw else 0) & 1 else set()
        manager.feed(key, sequence=(sequence + index + delta) & 0xFFFFFFFF, payload=segment, flags=flags)
    manager.feed(key, sequence=(sequence + max(0, len(raw) - cursor)) & 0xFFFFFFFF, payload=b"", flags={"fin"})
    return manager.diagnostics
