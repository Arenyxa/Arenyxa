from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine
from arenyxa.infrastructure.capture.packet_lab import OfflinePacketLab
from arenyxa.infrastructure.external_tools import ExternalToolCapability, ExternalToolProbe
from arenyxa.presentation.pages.network_analysis_actions import NetworkAnalysisActionsMixin
from arenyxa.qt_compat.QtWidgets import QPlainTextEdit


def _controlled_engine(monkeypatch, *, interface_error: bool = True):
    engine = PacketAnalysisEngine('tshark')
    monkeypatch.setattr(ExternalToolProbe, 'tshark', lambda **_kwargs: ExternalToolCapability('tshark', 'tshark', True, True, '4.6.9'))

    def run(args, timeout=None, check=True):
        if args[1:] == ['-D'] and interface_error:
            raise ArenyxaError('PACKET_ANALYSIS_COMMAND_FAILED', 'Unable to load Npcap (wpcap.dll)', domain='CAPTURE', context={'returncode': 13})
        if '-r' in args:
            raise ArenyxaError('PACKET_ANALYSIS_COMMAND_FAILED', 'Invalid capture', domain='CAPTURE')
        output = 'TShark 4.6.9\n' if args[1:] == ['-v'] else ''
        return subprocess.CompletedProcess(args, 0, output, '')

    monkeypatch.setattr(engine, '_run_process', run)
    return engine


def test_live_interface_failure_preserves_verified_offline_capability(monkeypatch):
    engine = _controlled_engine(monkeypatch)
    capabilities = engine.capabilities()
    assert capabilities.available
    assert capabilities.tshark == 'tshark'
    assert capabilities.version == 'TShark 4.6.9'
    assert not capabilities.live_capture_available
    assert 'Npcap' in capabilities.live_capture_detail
    assert capabilities.interfaces == []
    assert engine.available
    with pytest.raises(ArenyxaError, match='Npcap'):
        engine.interfaces()
    assert engine.available
    assert engine.capabilities().available


def test_empty_successful_interface_list_does_not_claim_live_capture(monkeypatch):
    engine = _controlled_engine(monkeypatch, interface_error=False)
    capabilities = engine.capabilities()
    assert capabilities.available
    assert capabilities.interfaces == []
    assert not capabilities.live_capture_available
    assert capabilities.live_capture_detail


@pytest.mark.parametrize('failure', ['version', 'fields'])
def test_actual_external_contract_failure_still_disables_backend(monkeypatch, failure):
    engine = PacketAnalysisEngine('tshark')

    def probe(executable, args, timeout):
        if args == ('-v',):
            return subprocess.CompletedProcess([executable, *args], 1 if failure == 'version' else 0, 'TShark 4.6.9', '')
        return subprocess.CompletedProcess([executable, *args], 0, 'F\tOther field\tother.field\n', '')

    monkeypatch.setattr(ExternalToolProbe, '_run_probe', probe)
    assert not engine.capabilities().available
    assert not engine.available


def test_decode_failure_after_live_failure_still_disables_backend(monkeypatch):
    engine = _controlled_engine(monkeypatch)
    engine.capabilities()
    with pytest.raises(ArenyxaError, match='Invalid capture'):
        engine._run_tshark(['-r', 'invalid.pcap'])
    assert not engine.available


def test_contract_failure_during_interface_probe_is_not_downgraded_to_live_only(monkeypatch):
    engine = _controlled_engine(monkeypatch)
    calls = 0

    def capability(**_kwargs):
        nonlocal calls
        calls += 1
        return ExternalToolCapability('tshark', 'tshark', True, calls < 4, '4.6.9', 'field contract failed')

    monkeypatch.setattr(ExternalToolProbe, 'tshark', capability)
    assert not engine.capabilities().available
    assert calls == 4
    assert not engine.available


def test_real_tshark_offline_summary_and_tree_survive_capability_probe(tmp_path: Path):
    executable = shutil.which('tshark')
    if not executable:
        pytest.skip('TShark offline backend is not installed')
    artifact = OfflinePacketLab.tls_client_hello(src_ip='192.0.2.10', dst_ip='198.51.100.20', server_name='gui.arenyxa.example')
    capture = OfflinePacketLab.write_pcap(tmp_path / 'hello.pcap', artifact, timestamp=1790985600)
    engine = PacketAnalysisEngine(executable)
    capabilities = engine.capabilities()
    assert capabilities.available
    assert capabilities.live_capture_available == bool(capabilities.interfaces)
    if not capabilities.live_capture_available:
        assert capabilities.live_capture_detail
    events = list(engine.iter_network_events(capture, CaptureSession('offline', CaptureSource.PCAP_IMPORT)))
    assert len(events) == 1
    assert events[0].host == 'gui.arenyxa.example'
    assert not events[0].metadata.get('native_decode')
    assert 'tls.handshake.version' in events[0].metadata['dissector_fields']
    assert 'gui.arenyxa.example' in json.dumps(engine.packet_tree(capture, 1))
    assert engine.available


class _ProjectionHarness(NetworkAnalysisActionsMixin):
    def __init__(self, events):
        self.model = SimpleNamespace(events=events)
        self.overview = QPlainTextEdit()
        self.headers_view = QPlainTextEdit()
        self.timing_view = QPlainTextEdit()
        self.protocol_view = QPlainTextEdit()
        self.inspectorChanged = SimpleNamespace(emit=lambda *_args: None)


@pytest.mark.parametrize(('protocol', 'metadata', 'expected'), [
    ('tls', {'native_layers': [{'name': 'tls', 'fields': {'server_name': 'gui.arenyxa.example', 'alpn': ['h2'], 'ja3_md5': 'synthetic-fingerprint', 'session_key': 'synthetic-secret'}}]}, 'synthetic-fingerprint'),
    ('dns', {'native_layers': [{'name': 'dns', 'fields': {'transaction_id': 42, 'question_records': [{'name': 'gui.arenyxa.example', 'type': 1, 'password': 'synthetic-secret'}], 'session_key': 'synthetic-secret'}}]}, 'gui.arenyxa.example'),
    ('tls', {'dissector_fields': {'tls.handshake.version': '0x0303', 'tls.handshake.extensions_alpn_str': 'h2', 'tls.keylog_file': 'synthetic-secret'}}, '0x0303'),
    ('dns', {'dissector_fields': {'dns.id': '42', 'dns.qry.type': '1', 'dns.txt': 'synthetic-secret'}}, 'dns.id'),
])
def test_selection_renders_only_current_offline_protocol_metadata(qapp, monkeypatch, protocol, metadata, expected):
    def forbidden(*_args, **_kwargs):
        raise AssertionError('Selection must not perform live DNS/TLS inspection')

    monkeypatch.setattr('arenyxa.presentation.pages.network_analysis_actions.TlsInspector.inspect', forbidden)
    monkeypatch.setattr('arenyxa.presentation.pages.network_analysis_actions.DnsAnalyzer.resolve', forbidden)
    event = {'protocol': protocol, 'host': 'gui.arenyxa.example', 'metadata': {**metadata, 'secret_refs': ['synthetic-secret']}}
    page = _ProjectionHarness([event, {'protocol': 'http', 'metadata': {}}])
    page.inspect_event(SimpleNamespace(isValid=lambda: True, row=lambda: 0), None)
    rendered = page.protocol_view.toPlainText()
    assert expected in rendered
    assert 'synthetic-secret' not in rendered
    assert json.loads(rendered)
    page.inspect_event(SimpleNamespace(isValid=lambda: True, row=lambda: 1), None)
    assert page.protocol_view.toPlainText() == ''
    page.protocol_view.setPlainText('old report')
    page.inspect_event(SimpleNamespace(isValid=lambda: False, row=lambda: -1), None)
    assert page.protocol_view.toPlainText() == ''


def test_native_metadata_projection_uses_captured_fields(tmp_path: Path, qapp):
    artifact = OfflinePacketLab.tls_client_hello(src_ip='192.0.2.10', dst_ip='198.51.100.20', server_name='gui.arenyxa.example')
    capture = OfflinePacketLab.write_pcap(tmp_path / 'native.pcap', artifact, timestamp=1790985600)
    engine = PacketAnalysisEngine()
    engine.executable = ''
    event = next(iter(engine.iter_network_events(capture, CaptureSession('native', CaptureSource.PCAP_IMPORT))))
    page = _ProjectionHarness([asdict(event)])
    page.inspect_event(SimpleNamespace(isValid=lambda: True, row=lambda: 0), None)
    assert 'gui.arenyxa.example' in page.protocol_view.toPlainText()
    assert 'supported_versions' in page.protocol_view.toPlainText()
