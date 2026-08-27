from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine

_ENGINE = ProtocolIntelligenceEngine()


def fuzz(data: bytes):
    return _ENGINE.decode_application_payload(bytes(data), source_port=443, destination_port=49152, transport="tcp")
