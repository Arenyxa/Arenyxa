from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
from typing import Any, Iterable

from arenyxa.infrastructure.capture.packet_models import PacketRecord, PacketExecutionProfile
from arenyxa.infrastructure.capture.network_evidence_graph import NetworkEvidenceGraphBuilder
from arenyxa.infrastructure.capture.tcp_session_analysis import TcpSessionAnalyzer
from arenyxa.infrastructure.capture.quic_session_analysis import QuicSessionAnalyzer
from arenyxa.infrastructure.capture.tls_session_analysis import TlsSessionAnalyzer
from arenyxa.infrastructure.capture.routing_forensics import RoutingControlPlaneAnalyzer
from arenyxa.infrastructure.capture.evpn_overlay_forensics import EvpnOverlayAnalyzer
from arenyxa.infrastructure.capture.evpn_policy_forensics import EvpnPolicyDomainAnalyzer
from arenyxa.infrastructure.capture.ipsec_session_forensics import IpsecSessionAnalyzer
from arenyxa.infrastructure.capture.wireguard_session_forensics import WireGuardSessionAnalyzer
from arenyxa.infrastructure.capture.gtp_tunnel_forensics import GtpTunnelForensicsAnalyzer
from arenyxa.infrastructure.capture.l2tp_session_forensics import L2tpSessionForensicsAnalyzer
from arenyxa.infrastructure.capture.realtime_media_forensics import RealtimeMediaSessionAnalyzer
from arenyxa.infrastructure.capture.mobile_core_forensics import MobileCoreForensicsAnalyzer
from arenyxa.infrastructure.capture.coap_session_forensics import CoapSessionForensicsAnalyzer
from arenyxa.infrastructure.capture.stun_turn_session_forensics import StunTurnSessionForensicsAnalyzer
from arenyxa.infrastructure.capture.bacnet_session_forensics import BacnetSessionForensicsAnalyzer
from arenyxa.infrastructure.capture.opcua_session_forensics import OpcuaSessionForensicsAnalyzer
from arenyxa.infrastructure.capture.enterprise_auth_forensics import EnterpriseAuthForensicsAnalyzer

MAX_DNS_PENDING = 100_000


def _epoch(timestamp: str) -> float | None:
    text = str(timestamp or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _native_layer(packet: PacketRecord, name: str) -> dict[str, Any]:
    layers = packet.metadata.get("native_layers")
    if not isinstance(layers, list):
        return {}
    for layer in layers:
        if isinstance(layer, dict) and layer.get("name") == name and isinstance(layer.get("fields"), dict):
            return dict(layer["fields"])
    return {}


def _field(packet: PacketRecord, name: str) -> str:
    fields = packet.metadata.get("dissector_fields")
    if not isinstance(fields, dict):
        return ""
    return str(fields.get(name) or "").split(",", 1)[0].strip()


def _dns_view(packet: PacketRecord) -> dict[str, Any] | None:
    native = _native_layer(packet, "dns") or _native_layer(packet, "mdns")
    if native:
        questions = native.get("question_records")
        first = questions[0] if isinstance(questions, list) and questions and isinstance(questions[0], dict) else {}
        return {
            "id": int(native.get("transaction_id") or 0),
            "response": bool(native.get("response")),
            "rcode": int(native.get("rcode") or 0),
            "name": str(first.get("name") or ""),
            "qtype": str(first.get("type_name") or first.get("type") or ""),
        }
    raw_id = _field(packet, "dns.id")
    response = _field(packet, "dns.flags.response")
    if not raw_id and not response and "dns" not in packet.protocols.casefold():
        return None
    try:
        txid = int(raw_id, 0) if raw_id else 0
    except (TypeError, ValueError, OverflowError):
        txid = 0
    try:
        rcode = int(_field(packet, "dns.flags.rcode") or 0, 0)
    except (TypeError, ValueError, OverflowError):
        rcode = 0
    return {
        "id": txid,
        "response": response in {"1", "true", "True"},
        "rcode": rcode,
        "name": packet.host,
        "qtype": _field(packet, "dns.qry.type"),
    }


def _tls_view(packet: PacketRecord) -> dict[str, Any] | None:
    native = _native_layer(packet, "tls")
    if native:
        certificates = native.get("certificate_chain") if isinstance(native.get("certificate_chain"), list) else []
        if not any(key in native for key in ("ja3", "ja4", "ja3s", "server_name", "alpn_protocols", "selected_cipher_suite", "certificate_chain")):
            return None
        return {
            "ja3": str(native.get("ja3") or ""),
            "ja3_md5": str(native.get("ja3_md5") or ""),
            "ja4": str(native.get("ja4") or ""),
            "ja3s": str(native.get("ja3s") or ""),
            "ja3s_md5": str(native.get("ja3s_md5") or ""),
            "sni": str(native.get("server_name") or ""),
            "alpn": tuple(
                str(item)
                for item in (
                    native.get("alpn")
                    if isinstance(native.get("alpn"), list)
                    else native.get("alpn_protocols")
                    if isinstance(native.get("alpn_protocols"), list)
                    else [native.get("selected_alpn")]
                    if native.get("selected_alpn")
                    else []
                )
                if str(item)
            )[:16],
            "cipher": str(native.get("selected_cipher_suite") or ""),
            "certificates": certificates[:16],
        }
    if "tls" not in packet.protocols.casefold():
        return None
    return {
        "ja3": "",
        "ja3_md5": "",
        "ja4": "",
        "ja3s": "",
        "ja3s_md5": "",
        "sni": packet.host,
        "alpn": tuple(item for item in _field(packet, "tls.handshake.extensions_alpn_str").split(",") if item)[:16],
        "cipher": _field(packet, "tls.handshake.ciphersuite"),
    }


def _tls_session_key(packet: PacketRecord, *, reverse: bool = False) -> tuple[str, int, str, int] | None:
    if packet.source_port is None or packet.destination_port is None:
        return None
    if reverse:
        return (packet.destination, int(packet.destination_port), packet.source, int(packet.source_port))
    return (packet.source, int(packet.source_port), packet.destination, int(packet.destination_port))


def _dns_name_matches(pattern: str, host: str) -> bool:
    candidate = str(pattern or "").strip().rstrip(".").casefold()
    target = str(host or "").strip().rstrip(".").casefold()
    if not candidate or not target:
        return False
    if candidate == target:
        return True
    if candidate.startswith("*."):
        suffix = candidate[1:]
        return target.endswith(suffix) and target.count(".") == candidate.count(".")
    return False


def _certificate_identity_match(certificate: dict[str, Any], host: str) -> tuple[bool, list[str]]:
    names = [str(item) for item in certificate.get("san_dns", []) if str(item)] if isinstance(certificate.get("san_dns"), list) else []
    # SAN is authoritative when present. CN fallback is deliberately omitted because
    # the native X.509 summary does not normalize CN into a separate trusted field.
    return any(_dns_name_matches(name, host) for name in names), names[:128]


def _tcp_syn_profile(packet: PacketRecord) -> dict[str, Any] | None:
    tcp = _native_layer(packet, "tcp")
    ip = _native_layer(packet, "ipv4") or _native_layer(packet, "ipv6")
    if tcp:
        flags = {str(item).casefold() for item in tcp.get("flags", [])}
        if "syn" not in flags or "ack" in flags:
            return None
        options = tcp.get("options") if isinstance(tcp.get("options"), list) else []
        option_names = [str(item.get("name") or item.get("kind") or "") for item in options if isinstance(item, dict)]
        mss = next((item.get("value") for item in options if isinstance(item, dict) and item.get("name") == "mss"), None)
        wscale = next((item.get("value") for item in options if isinstance(item, dict) and item.get("name") == "window-scale"), None)
        profile = {
            "ip_version": 6 if _native_layer(packet, "ipv6") else 4,
            "ttl_or_hop_limit": int(ip.get("ttl") or ip.get("hop_limit") or 0),
            "window": int(tcp.get("window") or 0),
            "mss": mss,
            "window_scale": wscale,
            "sack_permitted": "sack-permitted" in option_names,
            "timestamp": "timestamp" in option_names,
            "ecn": "ece" in flags or "cwr" in flags,
            "option_order": option_names,
        }
    else:
        flags_text = _field(packet, "tcp.flags")
        try:
            flags_value = int(flags_text, 0) if flags_text else 0
        except (TypeError, ValueError, OverflowError):
            return None
        if not (flags_value & 0x02) or flags_value & 0x10:
            return None
        profile = {
            "ip_version": 6 if ":ipv6:" in f":{packet.protocols.casefold()}:" else 4,
            "ttl_or_hop_limit": int(_field(packet, "ip.ttl") or _field(packet, "ipv6.hlim") or 0),
            "window": int(_field(packet, "tcp.window_size_value") or 0),
            "mss": int(_field(packet, "tcp.options.mss_val") or 0) or None,
            "window_scale": int(_field(packet, "tcp.options.wscale.shift") or 0) if _field(packet, "tcp.options.wscale.shift") else None,
            "sack_permitted": bool(_field(packet, "tcp.options.sack_perm")),
            "timestamp": bool(_field(packet, "tcp.options.timestamp.tsval")),
            "ecn": bool(flags_value & 0xC0),
            "option_order": [],
        }
    canonical = json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    profile["fingerprint_sha256"] = hashlib.sha256(b"arenyxa-tcp-syn-v1\x00" + canonical).hexdigest()
    return profile


def _arp_binding(packet: PacketRecord) -> tuple[str, str] | None:
    arp = _native_layer(packet, "arp")
    if arp:
        address = str(arp.get("sender_ip") or "")
        mac = str(arp.get("sender_mac") or "").casefold()
    else:
        address = _field(packet, "arp.src.proto_ipv4")
        mac = _field(packet, "arp.src.hw_mac").casefold()
    return (address, mac) if address and mac else None

def _quic_view(packet: PacketRecord) -> dict[str, Any] | None:
    native = _native_layer(packet, "quic")
    if native:
        return {
            "version": str(native.get("version_name") or native.get("version") or ""),
            "packet_type": str(native.get("packet_type") or ""),
            "dcid": str(native.get("destination_connection_id") or ""),
            "initial_decrypted": bool(native.get("initial_decryption")),
        }
    if "quic" not in packet.protocols.casefold():
        return None
    return {
        "version": _field(packet, "quic.version"),
        "packet_type": _field(packet, "quic.long.packet_type"),
        "dcid": _field(packet, "quic.dcid"),
        "initial_decrypted": False,
    }


class PacketForensicsMixin:
    """Bounded cross-packet correlations layered above native/external packet records."""

    def forensic_summary(
        self,
        capture: Any,
        *,
        display_filter: str = "",
        limit: int = 200_000,
        profile: PacketExecutionProfile | None = None,
    ) -> dict[str, Any]:
        packets = self.iter_packet_summaries(capture, display_filter=display_filter, limit=limit, profile=profile)
        return forensic_summary_from_packets(packets)


def _forensic_state() -> dict[str, Any]:
    return {
        "protocol_counts": Counter(), "tcp_findings": Counter(), "expert_counts": Counter(), "dns_rcodes": Counter(),
        "dns_pending": {}, "dns_latencies_ms": [], "dns_completed": 0, "tls_fingerprints": Counter(),
        "tls_server_fingerprints": Counter(), "tls_sni": Counter(), "tls_alpn": Counter(), "tls_client_sni_by_flow": {},
        "tls_certificate_sessions": [], "tls_certificate_name_mismatches": 0, "quic_versions": Counter(),
        "quic_initial_opened": 0, "tcp_syn_fingerprints": Counter(), "tcp_syn_profiles": {}, "arp_bindings": {},
        "http_status": Counter(), "grpc_streams": 0, "total": 0,
        "evidence_graph": NetworkEvidenceGraphBuilder(), "tcp_sessions": TcpSessionAnalyzer(), "quic_sessions": QuicSessionAnalyzer(),
        "tls_sessions": TlsSessionAnalyzer(), "routing_control_plane": RoutingControlPlaneAnalyzer(), "evpn_overlay": EvpnOverlayAnalyzer(),
        "evpn_policy": EvpnPolicyDomainAnalyzer(), "ipsec_sessions": IpsecSessionAnalyzer(), "wireguard_sessions": WireGuardSessionAnalyzer(),
        "gtp_tunnels": GtpTunnelForensicsAnalyzer(), "l2tp_sessions": L2tpSessionForensicsAnalyzer(),
        "realtime_media": RealtimeMediaSessionAnalyzer(), "mobile_core": MobileCoreForensicsAnalyzer(), "coap_sessions": CoapSessionForensicsAnalyzer(),
        "stun_turn_sessions": StunTurnSessionForensicsAnalyzer(), "bacnet_sessions": BacnetSessionForensicsAnalyzer(),
        "opcua_sessions": OpcuaSessionForensicsAnalyzer(), "enterprise_auth": EnterpriseAuthForensicsAnalyzer(),
    }


def _feed_forensic_analyzers(state: dict[str, Any], packet: PacketRecord) -> None:
    for name in (
        "evidence_graph", "tcp_sessions", "quic_sessions", "tls_sessions", "routing_control_plane", "evpn_overlay",
        "evpn_policy", "ipsec_sessions", "wireguard_sessions", "gtp_tunnels", "l2tp_sessions", "realtime_media",
        "mobile_core", "coap_sessions", "stun_turn_sessions", "bacnet_sessions", "opcua_sessions", "enterprise_auth",
    ):
        state[name].feed(packet)


def _feed_packet_metrics(state: dict[str, Any], packet: PacketRecord) -> None:
    state["total"] += 1
    state["protocol_counts"].update(part.casefold() for part in packet.protocols.split(":") if part)
    state["tcp_findings"].update(str(item) for item in packet.tcp_analysis)
    syn_profile = _tcp_syn_profile(packet)
    if syn_profile is not None:
        fingerprint = str(syn_profile["fingerprint_sha256"])
        state["tcp_syn_fingerprints"][fingerprint] += 1
        state["tcp_syn_profiles"].setdefault(fingerprint, syn_profile)
    binding = _arp_binding(packet)
    if binding is not None:
        state["arp_bindings"].setdefault(binding[0], set()).add(binding[1])
    if packet.status is not None:
        state["http_status"][int(packet.status)] += 1
    state["grpc_streams"] += int("grpc" in packet.protocols.casefold())
    for finding in packet.metadata.get("native_expert_findings", []):
        if isinstance(finding, dict) and (code := str(finding.get("code") or "")):
            state["expert_counts"][code] += 1


def _feed_dns_metrics(state: dict[str, Any], packet: PacketRecord, timestamp: float | None) -> None:
    dns = _dns_view(packet)
    if dns is None:
        return
    txid = int(dns["id"])
    if dns["response"]:
        state["dns_rcodes"][int(dns["rcode"])] += 1
        pending = state["dns_pending"].pop((packet.destination, packet.source, txid), None)
        if pending is not None and timestamp is not None:
            began, _name, _qtype = pending
            if timestamp >= began:
                state["dns_latencies_ms"].append((timestamp - began) * 1000.0)
                state["dns_completed"] += 1
    elif timestamp is not None and len(state["dns_pending"]) < MAX_DNS_PENDING:
        state["dns_pending"][(packet.source, packet.destination, txid)] = (timestamp, str(dns["name"]), str(dns["qtype"]))


def _feed_tls_metrics(state: dict[str, Any], packet: PacketRecord) -> None:
    tls = _tls_view(packet)
    if tls is None:
        return
    fingerprint = str(tls.get("ja3_md5") or tls.get("ja3") or "")
    server_fingerprint = str(tls.get("ja3s_md5") or tls.get("ja3s") or "")
    if fingerprint:
        state["tls_fingerprints"][fingerprint] += 1
    if server_fingerprint:
        state["tls_server_fingerprints"][server_fingerprint] += 1
    if tls.get("sni"):
        sni_value = str(tls["sni"])
        state["tls_sni"][sni_value] += 1
        flow = _tls_session_key(packet)
        if flow is not None and len(state["tls_client_sni_by_flow"]) < 100_000:
            state["tls_client_sni_by_flow"][flow] = sni_value
    for alpn in tls.get("alpn", ()):  # type: ignore[union-attr]
        state["tls_alpn"][str(alpn)] += 1
    certificates = tls.get("certificates") if isinstance(tls.get("certificates"), list) else []
    if not certificates:
        return
    reverse_flow = _tls_session_key(packet, reverse=True)
    sni_value = state["tls_client_sni_by_flow"].get(reverse_flow or (), "")
    leaf = certificates[0] if isinstance(certificates[0], dict) else {}
    matched, san_dns = _certificate_identity_match(leaf, sni_value) if sni_value else (False, [])
    if sni_value and san_dns and not matched:
        state["tls_certificate_name_mismatches"] += 1
    if len(state["tls_certificate_sessions"]) < 2048:
        state["tls_certificate_sessions"].append({
            "server_name": sni_value, "san_dns": san_dns, "name_match": matched if sni_value and san_dns else None,
            "leaf_sha256": str(leaf.get("sha256") or ""), "spki_sha256": str(leaf.get("spki_sha256") or ""),
            "not_valid_after": str(leaf.get("not_valid_after") or ""),
        })


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return round(ordered[index], 3)


def _forensic_summary(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "arenyxa.packet-forensics/v1", "packets": state["total"], "protocols": dict(state["protocol_counts"].most_common()),
        "tcp_findings": dict(state["tcp_findings"].most_common()),
        "tcp_syn_fingerprints": [{**state["tcp_syn_profiles"][key], "observations": count} for key, count in state["tcp_syn_fingerprints"].most_common(128)],
        "layer2": {"arp_binding_conflicts": [{"ip": address, "macs": sorted(macs)} for address, macs in sorted(state["arp_bindings"].items()) if len(macs) > 1]},
        "expert_findings": dict(state["expert_counts"].most_common()),
        "dns": {"completed_transactions": state["dns_completed"], "unmatched_queries": len(state["dns_pending"]),
                "rcode_counts": {str(key): value for key, value in sorted(state["dns_rcodes"].items())},
                "latency_ms": {"p50": _percentile(state["dns_latencies_ms"], 0.50), "p95": _percentile(state["dns_latencies_ms"], 0.95), "p99": _percentile(state["dns_latencies_ms"], 0.99)}},
        "tls": {"client_fingerprints": dict(state["tls_fingerprints"].most_common(128)), "server_fingerprints": dict(state["tls_server_fingerprints"].most_common(128)),
                "sni": dict(state["tls_sni"].most_common(128)), "alpn": dict(state["tls_alpn"].most_common(64)),
                "certificate_sessions": state["tls_certificate_sessions"], "certificate_name_mismatches": state["tls_certificate_name_mismatches"],
                "certificate_visibility_note": "Native certificate correlation applies to visible TLS 1.0-1.2 certificate flights or already-decrypted traffic; TLS 1.3 certificates require decryption evidence."},
        "quic": {"versions": dict(state["quic_versions"].most_common()), "public_initials_decrypted": state["quic_initial_opened"]},
        "http": {"status_counts": {str(key): value for key, value in sorted(state["http_status"].items())}, "grpc_packets": state["grpc_streams"]},
        **{name: state[name].finalize() for name in (
            "evidence_graph", "tcp_sessions", "quic_sessions", "tls_sessions", "routing_control_plane", "evpn_overlay", "evpn_policy",
            "ipsec_sessions", "wireguard_sessions", "gtp_tunnels", "l2tp_sessions", "realtime_media", "mobile_core", "coap_sessions",
            "stun_turn_sessions", "bacnet_sessions", "opcua_sessions", "enterprise_auth",
        )},
    }


def forensic_summary_from_packets(packets: Iterable[PacketRecord]) -> dict[str, Any]:
    state = _forensic_state()
    for packet in packets:
        _feed_forensic_analyzers(state, packet)
        _feed_packet_metrics(state, packet)
        timestamp = _epoch(packet.timestamp)
        _feed_dns_metrics(state, packet, timestamp)
        _feed_tls_metrics(state, packet)
        quic = _quic_view(packet)
        if quic is not None:
            state["quic_versions"][str(quic.get("version") or "unknown")] += 1
            state["quic_initial_opened"] += int(bool(quic.get("initial_decrypted")))
    return _forensic_summary(state)
