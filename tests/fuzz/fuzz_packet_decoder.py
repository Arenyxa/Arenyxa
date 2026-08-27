from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine

_ENGINE = ProtocolIntelligenceEngine()
_LINK_TYPES = ("ethernet", "raw-ip", "linux-sll", "linux-sll2", "ppp", "loopback", "ieee80211", "radiotap")


def fuzz(data: bytes):
    raw = bytes(data)
    if not raw:
        return None
    link_type = _LINK_TYPES[raw[0] % len(_LINK_TYPES)]
    payload = raw[1:] or b"\x00"
    return _ENGINE.decode_frame(payload, link_type=link_type)
