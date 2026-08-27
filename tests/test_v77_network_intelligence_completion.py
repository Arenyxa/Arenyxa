from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from arenyxa.application.command_runtime import ArenyxaCommandRuntime
from arenyxa.config import AppPaths
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import NetworkEvent
from arenyxa.enterprise.production_validation import ProductionValidationSuite
from arenyxa.infrastructure.capture import (
    BoundedEventStream,
    DynamicProtocolRegistry,
    DetectionRule,
    LiveIntelligencePipeline,
    OfflinePacketLab,
    PassiveDetectionEngine,
    ProtocolField,
    ProtocolPluginLoader,
    ProtocolRegistration,
    ThreatHunter,
)
from arenyxa.infrastructure.capture.native_capture import NativeCaptureReader
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine
from arenyxa.infrastructure.deployment_guard import is_loopback_bind, validate_storage_deployment


def _event(
    *,
    session: str = "session-1",
    protocol: str = "http",
    timestamp: str = "2026-08-22T00:00:00+00:00",
    host: str = "example.test",
    status: int | None = 200,
    url: str | None = "http://example.test/",
    headers: dict[str, str] | None = None,
    metadata: dict[str, object] | None = None,
) -> NetworkEvent:
    return NetworkEvent(
        session_id=session,
        source_type=CaptureSource.SYSTEM,
        protocol=protocol,
        direction="outbound",
        size=128,
        timestamp=timestamp,
        host=host,
        status=status,
        url=url,
        request_headers=headers or {},
        metadata=metadata or {},
    )


def test_dynamic_protocol_registry_supports_runtime_decoder_fields_and_clean_unregistration() -> None:
    registry = DynamicProtocolRegistry()
    registry.register(
        ProtocolRegistration(
            name="AcmeProto",
            source="plugin:test",
            fields=(ProtocolField("acme.value", "Value", "uint8", "acmeproto", source="plugin:test"),),
            decoder=lambda payload: {"value": payload[0]} if payload else None,
        )
    )
    assert registry.decode("acmeproto", b"\x07") == {"value": 7}
    assert registry.protocols(contains="acmeproto")[0]["decoder"] is True
    assert registry.fields(protocol="acmeproto")[0]["abbreviation"] == "acme.value"
    assert "plugin:test" in registry.snapshot()["sources"]
    assert registry.unregister("acmeproto", source="plugin:test") == 1
    assert registry.get("acmeproto") == ()
    assert registry.fields(protocol="acmeproto") == []


def test_protocol_plugin_loader_keeps_decoder_in_sandbox(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    (plugin_dir / "protocols.json").write_text(
        json.dumps(
            {
                "schema": "arenyxa.protocol-plugin/v1",
                "protocols": [
                    {
                        "name": "sandbox-demo",
                        "description": "sandboxed demo",
                        "transports": ["udp"],
                        "ports": [5555],
                        "magic_hex": "4143",
                        "fields": [{"abbreviation": "sandbox.demo.length", "type": "uint32"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest = SimpleNamespace(id="demo", capabilities=("protocol.dissector",), permissions={})

    class Manager:
        def discover(self):
            return [(manifest, plugin_dir)]

    class Sandbox:
        def invoke(self, _plugin_dir, payload, _permissions, _budget):
            raw = base64.b64decode(payload["payload_b64"])
            return {"handled": True, "decoded": {"length": len(raw)}}

    registry = DynamicProtocolRegistry()
    result = ProtocolPluginLoader(Manager(), Sandbox(), registry).load()  # type: ignore[arg-type]
    assert result["loaded_plugins"] == 1
    assert registry.decode("sandbox-demo", b"abcd") == {"length": 4}
    matched = registry.decode_matching(b"ACME", transport="udp", source_port=12000, destination_port=5555)
    assert matched == ("sandbox-demo", {"length": 4}, "plugin:demo")
    snapshot = registry.protocols(contains="sandbox-demo")[0]
    assert snapshot["transports"] == ["udp"] and snapshot["ports"] == [5555]
    assert registry.fields(protocol="sandbox-demo")[0]["source"] == "plugin:demo"




def test_runtime_protocol_registry_is_integrated_into_native_application_decode() -> None:
    from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine
    from arenyxa.infrastructure.capture.protocol_registry import global_protocol_registry

    registry = global_protocol_registry()
    source = "plugin:test-runtime-route"
    registry.register(
        ProtocolRegistration(
            name="runtime-demo",
            source=source,
            transports=("udp",),
            ports=(5555,),
            magic_hex="4143",
            decoder=lambda payload: {"marker": payload[:4].decode("ascii")},
        ),
        replace=True,
    )
    try:
        result = ProtocolIntelligenceEngine().decode_application_payload(
            b"ACME payload", source_port=40000, destination_port=5555, transport="udp"
        )
        assert result.application_protocol == "runtime-demo"
        assert result.layers[-1].fields["marker"] == "ACME"
        assert result.layers[-1].fields["detected_by"] == "runtime-protocol-registry"
        assert result.layers[-1].fields["decoder_source"] == source
    finally:
        registry.unregister("runtime-demo", source=source)


def test_unified_protocol_and_field_registry_has_native_catalog_without_tshark() -> None:
    engine = PacketAnalysisEngine(executable="")
    registry = engine.unified_protocol_registry(include_external=False)
    snapshot = registry.snapshot()
    assert snapshot["protocol_names"] >= 80
    assert snapshot["fields"] >= 100
    assert "native" in snapshot["protocol_sources"]
    assert "arenyxa-core" in snapshot["field_sources"]
    assert engine.unified_field_catalog(contains="frame.number", limit=10)[0]["abbreviation"] == "frame.number"


def test_bounded_event_stream_supports_replay_and_nonblocking_queue_consumers() -> None:
    stream = BoundedEventStream(capacity=128)
    with stream.subscribe_queue(topic_prefix="capture.alpha", capacity=1) as subscription:
        first = stream.publish("capture.alpha.event", {"value": 1})
        stream.publish("capture.alpha.event", {"value": 2})
        assert subscription.poll() == first
        assert subscription.poll() is None
        replay = stream.replay(topic_prefix="capture.alpha")
        assert [row["payload"]["value"] for row in replay] == [1, 2]
        stats = stream.stats()
        assert stats["queue_subscribers"] == 1
        assert stats["dropped_oldest"] >= 1  # queue backpressure is observable and non-blocking
    assert stream.stats()["subscriber_count"] == 0


def test_passive_detection_supports_bounded_declarative_runtime_rules() -> None:
    detector = PassiveDetectionEngine()
    detector.register_rule(DetectionRule(
        rule_id="CUSTOM-ADMIN-POST",
        title="POST to administration service",
        severity="high",
        protocols=("http",),
        destination_ports=(8080,),
        host_suffixes=("example.test",),
        methods=("POST",),
        confidence=0.91,
    ))
    event = _event(
        protocol="http",
        host="admin.example.test",
        url="http://admin.example.test/action",
        metadata={"dst_port": 8080},
    )
    event.method = "POST"
    alerts = detector.inspect(event)
    assert any(item.rule_id == "CUSTOM-ADMIN-POST" for item in alerts)
    assert detector.rules()[0]["severity"] == "high"
    assert detector.unregister_rule("CUSTOM-ADMIN-POST")


def test_passive_detection_flags_cleartext_secret_and_legacy_tls() -> None:
    detector = PassiveDetectionEngine()
    clear = _event(headers={"Authorization": "Bearer redacted"})
    tls = _event(protocol="tls", url="https://example.test/", metadata={"tls_version": "TLSv1.0"})
    clear_ids = {item.rule_id for item in detector.inspect(clear)}
    tls_ids = {item.rule_id for item in detector.inspect(tls)}
    assert "NET-CLEAR-CREDENTIAL" in clear_ids
    assert "TLS-LEGACY-VERSION" in tls_ids


def test_threat_hunter_correlates_beacon_dns_tunnel_and_lateral_movement() -> None:
    base = datetime(2026, 8, 22, tzinfo=timezone.utc)
    events: list[NetworkEvent] = []
    for index in range(7):
        events.append(
            _event(
                timestamp=(base + timedelta(seconds=index * 30)).isoformat(),
                host="beacon.example",
                metadata={"dst_ip": "203.0.113.10", "dst_port": 443},
                url="https://beacon.example/",
            )
        )
    entropy_label = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEfGhIjKlMnOp"
    for index in range(3):
        events.append(
            _event(
                protocol="dns",
                timestamp=(base + timedelta(seconds=300 + index)).isoformat(),
                host=f"{entropy_label}{index}.example.test",
                url=None,
                status=None,
                metadata={"dns.qry.name": f"{entropy_label}{index}.example.test"},
            )
        )
    for index in range(1, 7):
        events.append(
            _event(
                protocol="tcp",
                timestamp=(base + timedelta(seconds=500 + index)).isoformat(),
                host=f"10.0.0.{index}",
                url=None,
                status=None,
                metadata={"src_ip": "10.0.0.250", "dst_ip": f"10.0.0.{index}", "dst_port": 445},
            )
        )
    kinds = {row["kind"] for row in ThreatHunter().hunt(events)["findings"]}
    assert "periodic-beacon" in kinds
    assert "dns-tunneling" in kinds
    assert "lateral-movement-pattern" in kinds


def test_live_intelligence_pipeline_streams_and_detects() -> None:
    stream = BoundedEventStream(capacity=128)
    pipeline = LiveIntelligencePipeline(stream)
    event = _event(headers={"Authorization": "Bearer redacted"})
    with stream.subscribe_queue(topic_prefix="capture.session-1", capacity=8) as subscription:
        pipeline.on_capture_batch([event])
        rows = subscription.drain(limit=8)
    topics = {item.topic for item in rows}
    assert "capture.session-1.event" in topics
    assert "capture.session-1.alert" in topics
    snapshot = pipeline.live_snapshot("session-1")
    assert snapshot["events"] == 1
    assert snapshot["top_hosts"][0]["host"] == "example.test"
    assert snapshot["alerts"] >= 1
    assert snapshot["processing_errors"] == 0


def test_offline_packet_lab_outputs_valid_pcap_and_common_link_types(tmp_path: Path) -> None:
    udp = OfflinePacketLab.ipv4_udp(
        src_ip="192.0.2.10", dst_ip="198.51.100.20", src_port=12345, dst_port=53, payload="hello"
    )
    tcp = OfflinePacketLab.ipv4_tcp(
        src_ip="192.0.2.10", dst_ip="198.51.100.20", src_port=12345, dst_port=443, payload="x"
    )
    icmp = OfflinePacketLab.ipv4_icmp_echo(src_ip="192.0.2.10", dst_ip="198.51.100.20", payload="ping")
    assert udp.length > 28 and tcp.length > 40 and icmp.length > 28
    path = OfflinePacketLab.write_pcap(tmp_path / "fixture.pcap", udp, linktype=101, timestamp=1.5)
    packets = list(NativeCaptureReader().iter_packets(path))
    assert len(packets) == 1
    assert packets[0].link_type == "raw-ip"
    assert packets[0].data == bytes.fromhex(udp.hex)
    assert NativeCaptureReader.LINK_TYPES[9] == "ppp"
    assert NativeCaptureReader.LINK_TYPES[108] == "loopback"
    assert NativeCaptureReader.LINK_TYPES[276] == "linux-sll2"

    udp6 = OfflinePacketLab.ipv6_udp(
        src_ip="2001:db8::1", dst_ip="2001:db8::2", src_port=12345, dst_port=9999, payload="v6"
    )
    tcp6 = OfflinePacketLab.ipv6_tcp(
        src_ip="2001:db8::1", dst_ip="2001:db8::2", src_port=12345, dst_port=9999, payload="v6"
    )
    icmp6 = OfflinePacketLab.ipv6_icmp_echo(src_ip="2001:db8::1", dst_ip="2001:db8::2", payload="v6")
    arp = OfflinePacketLab.arp_request(src_mac="02:00:00:00:00:01", src_ip="192.0.2.10", target_ip="192.0.2.1")
    dns = OfflinePacketLab.dns_query(src_ip="192.0.2.10", dst_ip="198.51.100.53", name="example.test")
    dhcp = OfflinePacketLab.dhcp_discover(client_mac="02:00:00:00:00:01")
    http = OfflinePacketLab.http_request(
        src_ip="192.0.2.10", dst_ip="198.51.100.20", host="example.test", target="/health"
    )
    tls = OfflinePacketLab.tls_client_hello(
        src_ip="192.0.2.10", dst_ip="198.51.100.20", server_name="example.test"
    )
    assert {row.protocol for row in (udp6, tcp6, icmp6, arp, dns, dhcp, http, tls)} == {
        "udp6", "tcp6", "icmp6", "arp", "dns", "dhcp", "http", "tls-client-hello"
    }


def test_storage_guard_blocks_distributed_sqlite_and_warns_on_local_high_concurrency() -> None:
    assert is_loopback_bind("127.0.0.1")
    assert is_loopback_bind("::1")
    assert not is_loopback_bind("0.0.0.0")
    with pytest.raises(RuntimeError):
        validate_storage_deployment("sqlite", "server", bind_host="0.0.0.0")
    with pytest.raises(RuntimeError):
        validate_storage_deployment("sqlite", "worker")
    local = validate_storage_deployment("sqlite", "desktop", worker_concurrency=9)
    assert local.safe and local.warnings
    with pytest.raises(RuntimeError):
        validate_storage_deployment("sqlite", "desktop", worker_concurrency=16)
    assert validate_storage_deployment("postgresql", "server", distributed=True, bind_host="0.0.0.0", worker_concurrency=64).safe


def test_production_validation_concurrency_is_parameterized() -> None:
    suite = ProductionValidationSuite(soak_jobs=64, parallel_workers=17, batch_size=9)
    assert suite.soak_jobs == 64
    assert suite.parallel_workers == 17
    assert suite.batch_size == 9


def test_command_tree_covers_capture_and_packet_professional_actions() -> None:
    capture = set(ArenyxaCommandRuntime.COMMAND_TREE["capture"])
    packet = set(ArenyxaCommandRuntime.COMMAND_TREE["packet"])
    assert {"browser", "har-import", "pcap-import", "intelligence", "alerts", "rules", "rule-load", "stream-stats"} <= capture
    assert {"detect", "hunt", "build", "protocols", "fields"} <= packet


def test_terminal_secret_input_and_language_are_bound_to_runtime_settings() -> None:
    root = Path(__file__).resolve().parents[1]
    tools = "\n".join((root / rel).read_text(encoding="utf-8") for rel in (
        "src/arenyxa/presentation/pages/tools.py",
        "src/arenyxa/presentation/pages/tools_console.py",
    ))
    workspace = (root / "src/arenyxa/presentation/pages/tools_terminal_workspace.py").read_text(encoding="utf-8")
    assert "_secret_stdin_pending" in tools
    assert "textChanged.connect(self._update_secret_input_mode)" in tools
    assert "EchoMode.Password" in workspace
    assert "_terminal_locale" in workspace and "resolve_system_locale" in workspace
    assert 'command.casefold() == "stdin-secret"' in workspace


def test_win7_legacy_tree_does_not_depend_on_modern_conpty() -> None:
    root = Path(__file__).resolve().parents[1]
    legacy = root / "legacy" / "win7"
    if not legacy.exists():
        pytest.fail("legacy/win7 compatibility tree is missing")
    offenders: list[str] = []
    for path in legacy.rglob("*.py"):
        text = path.read_text(encoding="utf-8-sig")
        if "windows_conpty" in text or "WindowsConPtySession" in text:
            offenders.append(path.relative_to(root).as_posix())
    assert offenders == []


def test_command_runtime_har_pcap_and_packet_lab_end_to_end(tmp_path: Path) -> None:
    from arenyxa.bootstrap import bootstrap

    context = bootstrap(tmp_path / "data", start_scheduler=False)
    try:
        context.settings.developer_mode = True
        context.settings.developer_terms_version = 1
        context.settings.developer_terms_accepted_at = "2026-08-22T00:00:00+00:00"
        runtime = context.command_runtime
        assert runtime is not None

        har_path = context.paths.projects / "sample.har"
        har_path.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "test", "version": "1"},
                        "entries": [
                            {
                                "startedDateTime": "2026-08-22T00:00:00+00:00",
                                "time": 3,
                                "request": {
                                    "method": "GET",
                                    "url": "http://example.test/secret",
                                    "headers": [{"name": "Authorization", "value": "Bearer redacted"}],
                                    "cookies": [],
                                },
                                "response": {
                                    "status": 200,
                                    "headers": [],
                                    "bodySize": 5,
                                    "content": {"size": 5, "mimeType": "text/plain", "text": "hello"},
                                },
                                "cache": {},
                                "timings": {"wait": 3},
                            }
                        ],
                    }
                }
            ),
            encoding="utf-8",
        )
        imported = runtime.execute("capture har-import --file sample.har")
        har_session = imported["data"]["session"]["id"]
        assert imported["data"]["summary"]["request_count"] == 1
        intelligence = runtime.execute(f"capture intelligence {har_session}")["data"]
        assert intelligence["events"] == 1
        assert intelligence["alert_count"] >= 1
        alerts = runtime.execute(f"capture alerts {har_session}")["data"]
        assert alerts["alert_count"] >= 1

        rules_path = context.paths.projects / "network-rules.json"
        rules_path.write_text(json.dumps({"rules": [{
            "rule_id": "CLI-HTTP-EXAMPLE", "title": "Example HTTP traffic",
            "protocols": ["http"], "host_suffixes": ["example.test"], "severity": "low"
        }]}), encoding="utf-8")
        loaded_rules = runtime.execute("capture rule-load --file network-rules.json")["data"]
        assert loaded_rules["loaded"] == 1
        assert runtime.execute("capture rules")["data"]["count"] == 1

        packet = OfflinePacketLab.ipv4_udp(
            src_ip="192.0.2.10", dst_ip="198.51.100.20", src_port=40000, dst_port=53, payload=b"fixture"
        )
        pcap_path = context.paths.projects / "sample.pcap"
        OfflinePacketLab.write_pcap(pcap_path, packet, linktype=101, timestamp=1.0)
        pcap_import = runtime.execute("capture pcap-import --file sample.pcap --limit 100")
        assert pcap_import["data"]["decoded_packets"] == 1
        pcap_session = pcap_import["data"]["session"]["id"]
        assert runtime.execute(f"capture events {pcap_session}")["data"]

        detection = runtime.execute("packet detect sample.pcap --limit 100")["data"]
        hunt = runtime.execute("packet hunt sample.pcap --limit 100")["data"]
        assert detection["events_analyzed"] == 1
        assert hunt["events_analyzed"] == 1

        protocols = runtime.execute("packet protocols --limit 200")["data"]
        fields = runtime.execute("packet fields --contains frame.number --limit 20")["data"]
        assert protocols["registry"]["protocol_names"] >= 80
        assert any(row["abbreviation"] == "frame.number" for row in fields["fields"])

        built = runtime.execute(
            "packet build --protocol udp --src-ip 192.0.2.1 --dst-ip 198.51.100.2 "
            "--src-port 10000 --dst-port 53 --payload hello --output packet-lab-fixture.pcap"
        )["data"]
        assert Path(built["pcap_path"]).is_file()
        assert built["protocol"] == "udp"

        tls_fixture = runtime.execute(
            "packet build --protocol tls-client-hello --src-ip 192.0.2.1 --dst-ip 198.51.100.2 "
            "--server-name example.test --output tls-client-hello.pcap"
        )["data"]
        assert tls_fixture["protocol"] == "tls-client-hello"
        assert Path(tls_fixture["pcap_path"]).is_file()
    finally:
        context.shutdown()
