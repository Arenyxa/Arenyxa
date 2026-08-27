from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.protocol_expert_ipsec import analyze_ipsec_fields
from arenyxa.infrastructure.capture.protocol_expert_l2tp import analyze_l2tp_fields
from arenyxa.infrastructure.capture.protocol_expert_mobile_core import analyze_diameter_fields, analyze_pfcp_fields
from arenyxa.infrastructure.capture.protocol_expert_gtp import analyze_gtp_fields
from arenyxa.infrastructure.capture.protocol_expert_coap import analyze_coap_fields


@dataclass(frozen=True, slots=True)
class ProtocolExpertFinding:
    severity: str
    code: str
    protocol: str
    title: str
    detail: str
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "protocol": self.protocol,
            "title": self.title,
            "detail": self.detail,
            "evidence": dict(self.evidence),
        }


_SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "note": 3, "info": 4}
_WEAK_TLS_CIPHERS = {
    "0x0004",  # TLS_RSA_WITH_RC4_128_MD5
    "0x0005",  # TLS_RSA_WITH_RC4_128_SHA
    "0x000a",  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    "0x0016",  # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
}
_LEGACY_TLS_VERSIONS = {"0x0300", "0x0301", "0x0302"}


def _layer_rows(decoded: Any) -> Iterable[tuple[str, Mapping[str, Any]]]:
    for layer in getattr(decoded, "layers", ()):
        name = str(getattr(layer, "name", "") or "").casefold()
        fields = getattr(layer, "fields", {})
        yield name, fields if isinstance(fields, Mapping) else {}


def _finding(
    severity: str,
    code: str,
    protocol: str,
    title: str,
    detail: str,
    **evidence: Any,
) -> ProtocolExpertFinding:
    return ProtocolExpertFinding(severity, code, protocol, title, detail, evidence)


def _external_rows(protocol: str, fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    handlers = {
        "ike": lambda: analyze_ipsec_fields("ike", fields), "esp": lambda: analyze_ipsec_fields("esp", fields),
        "ah": lambda: analyze_ipsec_fields("ah", fields), "l2tp": lambda: analyze_l2tp_fields(fields),
        "gtp": lambda: analyze_gtp_fields(fields), "pfcp": lambda: analyze_pfcp_fields(fields),
        "diameter": lambda: analyze_diameter_fields(fields), "coap": lambda: analyze_coap_fields(fields),
    }
    handler = handlers.get(protocol)
    if handler is None:
        return []
    return [
        _finding(str(row["severity"]), str(row["code"]), protocol, str(row["title"]), str(row["detail"]), **dict(row.get("evidence") or {}))
        for row in handler()
    ]


def _layer_findings(protocol: str, fields: Mapping[str, Any], decoded: Any) -> list[ProtocolExpertFinding]:
    handlers = {
        "tls": _tls_findings, "quic": _quic_findings, "http2": _http2_findings, "http3": _http3_findings,
        "ntp": _ntp_findings, "ssh": _ssh_findings, "bgp": _bgp_findings, "ospf": _ospf_findings,
        "bfd": _bfd_findings, "vrrp": _vrrp_findings, "igmp": _igmp_findings, "pim": _pim_findings,
        "isis": _isis_findings, "ldp": _ldp_findings, "dhcp": _dhcp_findings, "dhcpv6": _dhcpv6_findings,
        "radius": _radius_findings, "snmp": _snmp_findings, "sctp": _sctp_findings, "ipv6-routing": _srv6_findings,
        "mpls": _mpls_findings, "vxlan": _vxlan_findings, "geneve": _geneve_findings, "modbus-tcp": _modbus_findings,
    }
    if protocol in {"dns", "mdns", "llmnr", "nbns"}:
        return _dns_findings(protocol, fields, getattr(decoded, "link_type", ""))
    if protocol in {"iec104", "dnp3"}:
        return _industrial_findings(protocol, fields)
    handler = handlers.get(protocol)
    if handler is not None:
        return handler(fields)
    return _external_rows(protocol, fields)


def analyze_protocol_decode(decoded: Any) -> list[ProtocolExpertFinding]:
    """Return bounded evidence-oriented defensive findings for a native decode result."""
    findings: list[ProtocolExpertFinding] = []
    if bool(getattr(decoded, "truncated", False)):
        findings.append(_finding(
            "warning", "DECODE_TRUNCATED", "frame", "Native decode stopped before the end of the frame",
            "The capture may be truncated, malformed, or outside the native decoder byte/structure budget.",
            warnings=list(getattr(decoded, "warnings", ()) or ())[:8],
        ))
    for protocol, fields in _layer_rows(decoded):
        findings.extend(_layer_findings(protocol, fields, decoded))
    findings.sort(key=lambda item: (_SEVERITY_ORDER.get(item.severity, 99), item.protocol, item.code))
    return findings[:256]

def _tls_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    supported = {str(item).casefold() for item in fields.get("supported_versions", ()) if str(item)}
    selected = str(fields.get("selected_version") or "").casefold()
    hello_version = selected or (max(supported) if supported else "")
    if hello_version in _LEGACY_TLS_VERSIONS:
        rows.append(_finding(
            "warning", "TLS_LEGACY_VERSION", "tls", "Legacy TLS version observed",
            "The negotiated/advertised handshake metadata indicates a pre-TLS-1.2 protocol version.",
            version=hello_version,
        ))
    offered = {str(item).casefold() for item in fields.get("cipher_suites", ()) if str(item)}
    weak = sorted(offered & _WEAK_TLS_CIPHERS)
    if weak:
        rows.append(_finding(
            "note", "TLS_WEAK_CIPHER_OFFERED", "tls", "Legacy cipher suite offered",
            "A ClientHello offered one or more legacy cipher suites. This does not prove that the server selected them.",
            cipher_suites=weak,
        ))
    if bool(fields.get("malformed_extensions")):
        rows.append(_finding(
            "warning", "TLS_EXTENSION_LAYOUT_INVALID", "tls", "Malformed TLS extension layout",
            "The ClientHello extension vector did not fit its declared bounds.",
        ))
    if fields.get("handshake_type") == 1 and not str(fields.get("server_name") or ""):
        rows.append(_finding(
            "info", "TLS_CLIENT_HELLO_WITHOUT_SNI", "tls", "ClientHello without SNI",
            "No Server Name Indication value was present in the decoded ClientHello.",
        ))
    for index, certificate in enumerate(fields.get("certificate_chain", ()) if isinstance(fields.get("certificate_chain"), list) else ()):
        if not isinstance(certificate, Mapping):
            continue
        expiry = _parse_iso(str(certificate.get("not_valid_after") or ""))
        start = _parse_iso(str(certificate.get("not_valid_before") or ""))
        now = datetime.now(timezone.utc)
        if expiry is not None and expiry < now:
            rows.append(_finding(
                "high", "TLS_CERTIFICATE_EXPIRED", "tls", "Expired TLS certificate observed",
                "A certificate in the visible TLS 1.0-1.2 certificate flight is past its notAfter time.",
                chain_index=index, subject=str(certificate.get("subject") or "")[:512], not_valid_after=expiry.isoformat(),
            ))
        elif start is not None and start > now:
            rows.append(_finding(
                "warning", "TLS_CERTIFICATE_NOT_YET_VALID", "tls", "TLS certificate is not yet valid",
                "A certificate in the visible certificate flight has a notBefore time in the future.",
                chain_index=index, subject=str(certificate.get("subject") or "")[:512], not_valid_before=start.isoformat(),
            ))
        if str(certificate.get("public_key_type") or "").startswith("RSA") and int(certificate.get("public_key_bits") or 0) < 2048:
            rows.append(_finding(
                "high", "TLS_RSA_KEY_TOO_SMALL", "tls", "Small RSA public key observed",
                "The certificate exposes an RSA public key below the 2048-bit operational baseline.",
                chain_index=index, public_key_bits=int(certificate.get("public_key_bits") or 0),
            ))
        if str(certificate.get("signature_hash") or "").casefold() in {"md5", "sha1"}:
            rows.append(_finding(
                "warning", "TLS_LEGACY_CERT_SIGNATURE_HASH", "tls", "Legacy certificate signature hash observed",
                "The certificate signature metadata uses a legacy digest algorithm.",
                chain_index=index, signature_hash=str(certificate.get("signature_hash") or ""),
            ))
    return rows


def _parse_iso(value: str) -> datetime | None:
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _dns_findings(protocol: str, fields: Mapping[str, Any], link_type: str) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    rcode = int(fields.get("rcode") or 0)
    if bool(fields.get("response")) and rcode:
        severity = "warning" if rcode in {2, 5} else "note"
        rows.append(_finding(
            severity, "DNS_NONZERO_RCODE", protocol, "DNS response returned an error code",
            "The response code is non-zero; correlate with the query and resolver/server health before treating it as anomalous.",
            rcode=rcode,
        ))
    if bool(fields.get("truncated")):
        rows.append(_finding(
            "note", "DNS_TRUNCATED_RESPONSE", protocol, "DNS response is truncated",
            "The TC flag is set; clients normally retry using a transport that can carry the complete answer.",
        ))
    for record in fields.get("additional_records", ()) if isinstance(fields.get("additional_records"), list) else ():
        if not isinstance(record, Mapping) or str(record.get("type_name")) != "OPT":
            continue
        edns_version = int(record.get("edns_version") or 0)
        if edns_version != 0:
            rows.append(_finding(
                "warning", "DNS_EDNS_VERSION_NONZERO", protocol, "Unexpected EDNS version",
                "EDNS version 0 is the widely deployed baseline; a non-zero value deserves protocol compatibility review.",
                edns_version=edns_version,
            ))
        udp_size = int(record.get("udp_payload_size") or 0)
        if str(link_type).startswith("udp") and udp_size > 4096:
            rows.append(_finding(
                "note", "DNS_LARGE_EDNS_UDP_SIZE", protocol, "Large EDNS UDP payload size advertised",
                "Large UDP payload advertisements can increase fragmentation exposure on paths with smaller MTUs.",
                udp_payload_size=udp_size,
            ))
    return rows


def _quic_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if fields.get("long_header") and not fields.get("fixed_bit", True):
        rows.append(_finding(
            "warning", "QUIC_FIXED_BIT_CLEAR", "quic", "QUIC fixed bit is clear",
            "A QUIC long header normally carries the fixed bit. The packet may be malformed or intentionally greased by an extension mechanism.",
        ))
    if str(fields.get("packet_type") or "") == "Version Negotiation":
        rows.append(_finding(
            "info", "QUIC_VERSION_NEGOTIATION", "quic", "QUIC version negotiation observed",
            "The endpoint returned a version-negotiation packet; correlate with client versions and retry behavior.",
            destination_connection_id=str(fields.get("destination_connection_id") or "")[:64],
        ))
    version_name = str(fields.get("version_name") or "")
    if version_name == "unknown" and fields.get("version"):
        rows.append(_finding(
            "note", "QUIC_UNKNOWN_VERSION", "quic", "Unknown QUIC version observed",
            "The version is not one of the native decoder's standardized v1/v2 identifiers. External dissectors may recognize newer or experimental versions.",
            version=str(fields.get("version")),
        ))
    return rows


def _http2_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    for frame in fields.get("frames", ()) if isinstance(fields.get("frames"), list) else ():
        if not isinstance(frame, Mapping):
            continue
        if frame.get("type") == "SETTINGS":
            ids = [int(item.get("id") or -1) for item in frame.get("settings", ()) if isinstance(item, Mapping)]
            if len(ids) != len(set(ids)):
                rows.append(_finding(
                    "warning", "HTTP2_DUPLICATE_SETTING", "http2", "Duplicate HTTP/2 SETTINGS identifier",
                    "The same SETTINGS identifier appeared more than once in one frame.",
                    setting_ids=ids[:64],
                ))
    return rows


def _http3_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    for frame in fields.get("frames", ()) if isinstance(fields.get("frames"), list) else ():
        if not isinstance(frame, Mapping) or frame.get("type") != "SETTINGS":
            continue
        ids = [int(item.get("id") or -1) for item in frame.get("settings", ()) if isinstance(item, Mapping)]
        if len(ids) != len(set(ids)):
            rows.append(_finding(
                "warning", "HTTP3_DUPLICATE_SETTING", "http3", "Duplicate HTTP/3 SETTINGS identifier",
                "HTTP/3 peers must not send duplicate setting identifiers in one SETTINGS frame.",
                setting_ids=ids[:64],
            ))
    return rows


def _ntp_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if int(fields.get("stratum") or 0) == 0:
        rows.append(_finding(
            "info", "NTP_KISS_OR_UNSPECIFIED", "ntp", "NTP stratum zero observed",
            "Stratum zero can represent an unsynchronized/reference control response; inspect the complete NTP payload externally when needed.",
        ))
    leap = int(fields.get("leap_indicator") or 0)
    if leap == 3:
        rows.append(_finding(
            "warning", "NTP_UNSYNCHRONIZED", "ntp", "NTP server reports unsynchronized time",
            "Leap indicator 3 signals an unsynchronized clock and can affect distributed lease/clock assumptions.",
        ))
    return rows


def _bgp_extended_communities(attributes: list[Any], rows: list[ProtocolExpertFinding]) -> set[str]:
    encapsulations: set[str] = set()
    for attribute in attributes[:512]:
        if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != "EXTENDED_COMMUNITIES":
            continue
        if bool(attribute.get("malformed")):
            rows.append(_finding("warning", "BGP_EXTENDED_COMMUNITIES_MALFORMED", "bgp", "BGP Extended Communities vector is not 8-octet aligned",
                                 "The Extended Communities path attribute length is structurally invalid; individual community semantics were not inferred past the validated boundary."))
        communities = attribute.get("communities") if isinstance(attribute.get("communities"), list) else []
        for community in communities[:512]:
            if not isinstance(community, Mapping):
                continue
            if str(community.get("name") or "") == "encapsulation":
                encapsulations.add(str(community.get("tunnel_type_name") or ""))
            if bool(community.get("reserved_nonzero")) or bool(community.get("reserved_bytes_nonzero")) or int(community.get("reserved") or 0):
                rows.append(_finding("note", "BGP_EVPN_EXTENDED_COMMUNITY_RESERVED_NONZERO", "bgp", "EVPN/BGP Extended Community reserved field is non-zero",
                                     "A recognized EVPN or encapsulation Extended Community contains non-zero reserved bits; retain as interoperability evidence rather than inferring compromise.",
                                     community=str(community.get("name") or "extended-community")))
    return encapsulations


def _bgp_tunnel_findings(attributes: list[Any], rows: list[ProtocolExpertFinding], encapsulations: set[str]) -> None:
    evpn_update = any(isinstance(a, Mapping) and int(a.get("afi") or 0) == 25 and int(a.get("safi") or 0) == 70 for a in attributes[:512])
    for attribute in attributes[:512]:
        if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != "TUNNEL_ENCAPSULATION":
            continue
        if bool(attribute.get("malformed")):
            rows.append(_finding("warning", "BGP_TUNNEL_ENCAPSULATION_MALFORMED", "bgp", "BGP Tunnel Encapsulation attribute is malformed",
                                 "A Tunnel Encapsulation TLV or sub-TLV exceeded its declared boundary or failed structural validation; opaque values were not retained."))
        tunnels = attribute.get("tunnels") if isinstance(attribute.get("tunnels"), list) else []
        for tunnel in tunnels[:256]:
            if not isinstance(tunnel, Mapping):
                continue
            tunnel_name = str(tunnel.get("tunnel_type_name") or "")
            if tunnel_name:
                encapsulations.add(tunnel_name)
            endpoint_count = int(tunnel.get("tunnel_egress_endpoint_count") or 0)
            if evpn_update and endpoint_count != 1:
                rows.append(_finding("warning", "BGP_TUNNEL_EGRESS_ENDPOINT_CARDINALITY", "bgp", "EVPN Tunnel Encapsulation TLV does not contain exactly one egress endpoint",
                                     "For EVPN and the other AFI/SAFI combinations scoped by RFC 9012, each Tunnel TLV requires exactly one Tunnel Egress Endpoint sub-TLV.",
                                     tunnel_type=tunnel_name, endpoint_count=endpoint_count))
            for sub_tlv in (tunnel.get("sub_tlvs") if isinstance(tunnel.get("sub_tlvs"), list) else [])[:512]:
                if not isinstance(sub_tlv, Mapping):
                    continue
                if bool(sub_tlv.get("malformed")) or bool(sub_tlv.get("malformed_reserved_zero")):
                    rows.append(_finding("warning", "BGP_TUNNEL_SUBTLV_MALFORMED", "bgp", "BGP Tunnel Encapsulation sub-TLV is malformed",
                                         "A recognized Tunnel Encapsulation sub-TLV contains an invalid length or reserved value.",
                                         tunnel_type=tunnel_name, sub_tlv=str(sub_tlv.get("name") or sub_tlv.get("type") or "unknown")))
                if bool(sub_tlv.get("reserved_flag_bits_nonzero")) or bool(sub_tlv.get("reserved_bytes_nonzero")) or bool(sub_tlv.get("reserved_nonzero")):
                    rows.append(_finding("note", "BGP_TUNNEL_RESERVED_NONZERO", "bgp", "BGP Tunnel Encapsulation reserved field is non-zero",
                                         "Reserved tunnel-encapsulation fields were retained as interoperability evidence without inferring malicious intent.",
                                         tunnel_type=tunnel_name, sub_tlv=str(sub_tlv.get("name") or sub_tlv.get("type") or "unknown")))


def _bgp_pmsi_findings(attributes: list[Any], rows: list[ProtocolExpertFinding], encapsulations: set[str]) -> None:
    evpn_imet = any(
        isinstance(a, Mapping) and int(a.get("afi") or 0) == 25 and int(a.get("safi") or 0) == 70
        and any(isinstance(r, Mapping) and int(r.get("route_type") or 0) == 3 for r in (a.get("nlri") if isinstance(a.get("nlri"), list) else [])[:4096])
        for a in attributes[:512]
    )
    for attribute in attributes[:512]:
        if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != "PMSI_TUNNEL":
            continue
        if bool(attribute.get("malformed")):
            rows.append(_finding("warning", "BGP_PMSI_TUNNEL_MALFORMED", "bgp", "BGP PMSI Tunnel attribute is malformed",
                                 "The PMSI Tunnel attribute contains an undefined tunnel type or a tunnel identifier that could not be parsed within its defined bounds.",
                                 tunnel_type=str(attribute.get("tunnel_type_name") or ""), parse_error=str(attribute.get("parse_error") or "")[:256]))
            continue
        tunnel_type = int(attribute.get("tunnel_type") or 0)
        if evpn_imet and ("vxlan" in encapsulations or "nvgre" in encapsulations) and tunnel_type not in {3, 4, 5, 6}:
            rows.append(_finding("warning", "BGP_EVPN_PMSI_TUNNEL_TYPE_UNSUPPORTED", "bgp", "EVPN IMET advertises a PMSI tunnel type outside the VXLAN/NVGRE profile",
                                 "For EVPN VXLAN/NVGRE IMET signaling, the interoperable PMSI tunnel types are PIM-SSM, PIM-SM, BIDIR-PIM, and Ingress Replication.",
                                 tunnel_type=tunnel_type, tunnel_type_name=str(attribute.get("tunnel_type_name") or "")))


def _bgp_evpn_route_findings(attributes: list[Any], rows: list[ProtocolExpertFinding]) -> None:
    for attribute in attributes[:512]:
        if not isinstance(attribute, Mapping) or int(attribute.get("afi") or 0) != 25 or int(attribute.get("safi") or 0) != 70:
            continue
        key = "nlri" if str(attribute.get("name") or "") == "MP_REACH_NLRI" else "withdrawn_nlri"
        for route in (attribute.get(key) if isinstance(attribute.get(key), list) else [])[:4096]:
            if not isinstance(route, Mapping):
                continue
            if bool(route.get("malformed")):
                rows.append(_finding("warning", "BGP_EVPN_NLRI_MALFORMED", "bgp", "Malformed EVPN NLRI retained as bounded evidence",
                                     "The EVPN route header was recognized but the route-type-specific body failed structural validation; opaque route bytes were not retained.",
                                     route_type=int(route.get("route_type") or 0), parse_error=str(route.get("parse_error") or "")[:256]))
                continue
            if int(route.get("route_type") or 0) == 5:
                esi = route.get("ethernet_segment_identifier") if isinstance(route.get("ethernet_segment_identifier"), Mapping) else {}
                gateway = str(route.get("gateway_ip") or "")
                if not bool(esi.get("zero", True)) and gateway not in {"", "0.0.0.0", "::"}:
                    rows.append(_finding("warning", "BGP_EVPN_RT5_MULTIPLE_OVERLAY_INDEXES", "bgp", "EVPN RT-5 carries both non-zero ESI and gateway IP",
                                         "EVPN IP Prefix routes should not simultaneously select ESI and gateway-IP overlay indexes; this combination requires treat-as-withdraw handling by compliant receivers.",
                                         prefix=str(route.get("ip_prefix") or ""), gateway_ip=gateway))


def _bgp_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    message = str(fields.get("message_name") or "")
    if message == "notification":
        rows.append(_finding("warning", "BGP_NOTIFICATION", "bgp", "BGP NOTIFICATION observed",
                             "A BGP speaker emitted a NOTIFICATION and normally closes the session; correlate the error code with the adjacent control-plane exchange.",
                             error_code=int(fields.get("error_code") or 0), error_subcode=int(fields.get("error_subcode") or 0)))
    if message == "open" and 0 < int(fields.get("hold_time") or 0) < 3:
        rows.append(_finding("note", "BGP_UNUSUALLY_LOW_HOLD_TIME", "bgp", "Very low BGP hold timer advertised",
                             "The OPEN message advertises a non-zero hold time below three seconds; verify that both peers intentionally use an aggressive timer profile.",
                             hold_time=int(fields.get("hold_time") or 0)))
    attributes = fields.get("path_attributes") if isinstance(fields.get("path_attributes"), list) else []
    encapsulations = _bgp_extended_communities(attributes, rows)
    _bgp_tunnel_findings(attributes, rows, encapsulations)
    _bgp_pmsi_findings(attributes, rows, encapsulations)
    if "vxlan" in encapsulations and "mpls" in encapsulations:
        rows.append(_finding("warning", "BGP_EVPN_INCOMPATIBLE_ENCAPSULATIONS", "bgp", "EVPN route advertises VXLAN and MPLS encapsulation together",
                             "EVPN VXLAN and MPLS procedures use the service field differently and should not be advertised together for the same EVPN route set.",
                             encapsulations=sorted(encapsulations)))
    _bgp_evpn_route_findings(attributes, rows)
    return rows

def _ospf_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    version = int(fields.get("version") or 0)
    packet_name = str(fields.get("packet_type_name") or "")
    if bool(fields.get("truncated")):
        rows.append(_finding(
            "warning", "OSPF_PACKET_TRUNCATED", "ospf", "OSPF packet shorter than its declared length",
            "The OSPF packet header advertises more bytes than were available to the native decoder.",
            declared_length=int(fields.get("packet_length") or 0), captured_length=int(fields.get("captured_length") or 0),
        ))
    if bool(fields.get("body_malformed")):
        rows.append(_finding(
            "warning", "OSPF_BODY_MALFORMED", "ospf", "OSPF packet body is structurally incomplete or malformed",
            "The common OSPF header was preserved, but the packet-type-specific body could not be decoded within its declared bounds.",
            packet_type_name=str(fields.get("packet_type_name") or ""), body_error=str(fields.get("body_error") or "")[:256],
        ))
    if version == 3 and int(fields.get("reserved") or 0) != 0:
        rows.append(_finding(
            "note", "OSPFV3_RESERVED_NONZERO", "ospf", "OSPFv3 reserved header field is non-zero",
            "The reserved header octet is expected to be zero when sent; receivers ignore it, so this is diagnostic rather than a vulnerability claim.",
            reserved=int(fields.get("reserved") or 0), instance_id=int(fields.get("instance_id") or 0),
        ))
    if packet_name == "hello":
        hello = int(fields.get("hello_interval_seconds") or 0)
        dead = int(fields.get("router_dead_interval_seconds") or 0)
        if hello <= 0 or dead <= 0 or (hello and dead < hello):
            rows.append(_finding(
                "warning", "OSPF_HELLO_TIMER_INCONSISTENT", "ospf", "OSPF Hello timer relationship is inconsistent",
                "The observed Hello/Dead timer values are zero or the dead interval is shorter than the hello interval; verify the neighboring interface configuration.",
                hello_interval_seconds=hello, router_dead_interval_seconds=dead,
            ))
    if packet_name == "link-state-update":
        advertised = int(fields.get("advertised_lsa_count") or 0)
        decoded = int(fields.get("decoded_lsa_count") or 0)
        if bool(fields.get("invalid_lsa_length")):
            rows.append(_finding(
                "warning", "OSPF_LSA_LENGTH_INVALID", "ospf", "Invalid OSPF LSA length observed",
                "An LSA length was below the common header size or extended beyond the packet boundary, so native parsing stopped at the evidence boundary.",
                advertised_lsa_count=advertised, decoded_lsa_count=decoded,
            ))
        elif advertised != decoded and not bool(fields.get("lsa_limit_reached")):
            rows.append(_finding(
                "note", "OSPF_LSA_COUNT_MISMATCH", "ospf", "OSPF Link State Update count does not match decoded LSAs",
                "The advertised LSA count differs from the number of structurally complete LSAs visible in this packet.",
                advertised_lsa_count=advertised, decoded_lsa_count=decoded, trailing_bytes=int(fields.get("trailing_bytes") or 0),
            ))
        lsas = fields.get("lsas") if isinstance(fields.get("lsas"), list) else []
        malformed = [
            row for row in lsas
            if isinstance(row, Mapping) and bool(row.get("body_malformed"))
        ]
        if malformed:
            rows.append(_finding(
                "warning", "OSPF_LSA_BODY_MALFORMED", "ospf", "OSPF LSA body is structurally inconsistent",
                "One or more recognized LSA bodies could not be decoded within their declared LSA boundary. The common LSA header remains usable for correlation.",
                malformed_lsa_count=len(malformed),
                lsa_types=[str(row.get("ls_type_name") or "unknown") for row in malformed[:16]],
            ))
    return rows


def _bfd_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    state = str(fields.get("state_name") or "")
    if state in {"down", "admin-down"}:
        rows.append(_finding(
            "note", "BFD_SESSION_NOT_UP", "bfd", "BFD session is not in Up state",
            "The observed BFD control packet reports a non-Up session state. Correlate both directions and routing protocol state before assigning a fault domain.",
            state=state, diagnostic=int(fields.get("diagnostic") or 0),
        ))
    if int(fields.get("detect_multiplier") or 0) == 0:
        rows.append(_finding(
            "warning", "BFD_DETECT_MULTIPLIER_ZERO", "bfd", "BFD detection multiplier is zero",
            "A zero detection multiplier is not a usable failure-detection profile and should be verified against the peer implementation.",
        ))
    if bool(fields.get("authentication_present")) and int(fields.get("authentication_bytes") or 0) == 0:
        rows.append(_finding(
            "warning", "BFD_AUTH_DATA_MISSING", "bfd", "BFD authentication flag has no captured authentication section",
            "The authentication-present bit is set but no authentication bytes are visible within the declared packet length.",
        ))
    return rows


def _vrrp_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    advertised = int(fields.get("address_count") or 0)
    decoded = int(fields.get("decoded_address_count") or 0)
    if advertised != decoded:
        rows.append(_finding(
            "warning", "VRRP_ADDRESS_COUNT_MISMATCH", "vrrp", "VRRP address count exceeds captured addresses",
            "The advertisement declares more virtual addresses than were structurally visible in the packet.",
            advertised_address_count=advertised, decoded_address_count=decoded,
        ))
    if int(fields.get("priority") or 0) == 0:
        rows.append(_finding(
            "note", "VRRP_MASTER_RELINQUISH", "vrrp", "VRRP priority zero advertisement observed",
            "Priority zero is used to indicate that the current master is relinquishing responsibility; correlate subsequent advertisements to verify failover convergence.",
            virtual_router_id=int(fields.get("virtual_router_id") or 0),
        ))
    if int(fields.get("version") or 0) == 3 and int(fields.get("reserved") or 0) != 0:
        rows.append(_finding(
            "note", "VRRPV3_RESERVED_NONZERO", "vrrp", "VRRPv3 reserved bits are non-zero",
            "Reserved bits in the Max Advertisement Interval field are expected to be zero when transmitted.",
            reserved=int(fields.get("reserved") or 0),
        ))
    return rows


def _igmp_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if bool(fields.get("sources_truncated")) or bool(fields.get("records_truncated")):
        rows.append(_finding(
            "warning", "IGMP_STRUCTURE_TRUNCATED", "igmp", "IGMPv3 source/group record structure is truncated",
            "The message ended before all declared source or group-record entries were available.",
            type_name=str(fields.get("type_name") or ""),
        ))
    return rows


def _pim_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if bool(fields.get("options_truncated")):
        rows.append(_finding(
            "warning", "PIM_HELLO_OPTIONS_TRUNCATED", "pim", "PIM Hello option vector is truncated",
            "A PIM Hello option length extended beyond the available packet boundary.",
        ))
    if str(fields.get("type_name") or "") == "hello" and fields.get("holdtime_seconds") == 0:
        rows.append(_finding(
            "note", "PIM_HOLDTIME_ZERO", "pim", "PIM Hello advertises zero holdtime",
            "A zero PIM Hello holdtime requests immediate neighbor timeout; correlate with adjacency changes before treating it as a fault.",
        ))
    return rows


def _isis_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if bool(fields.get("tlvs_truncated")):
        rows.append(_finding(
            "warning", "ISIS_TLV_VECTOR_TRUNCATED", "isis", "IS-IS TLV vector is structurally incomplete",
            "The IS-IS PDU ended before all TLV bytes could be decoded within the packet boundary.",
            pdu_type_name=str(fields.get("pdu_type_name") or ""),
        ))
    if str(fields.get("pdu_type_name") or "").endswith("hello") and int(fields.get("holding_timer_seconds") or 0) == 0:
        rows.append(_finding(
            "note", "ISIS_HOLDING_TIMER_ZERO", "isis", "IS-IS Hello advertises zero holding time",
            "A zero holding timer requests immediate adjacency expiration; correlate subsequent Hellos and LSP state before assigning a fault cause.",
        ))
    tlvs = fields.get("tlvs") if isinstance(fields.get("tlvs"), list) else []
    malformed_names = sorted({
        str(tlv.get("name") or "unknown")
        for tlv in tlvs
        if isinstance(tlv, Mapping)
        and str(tlv.get("name") or "") in {"extended-is-reachability", "extended-ipv4-reachability", "ipv6-reachability"}
        and bool(tlv.get("malformed"))
    })
    if malformed_names:
        rows.append(_finding(
            "warning", "ISIS_REACHABILITY_MALFORMED", "isis", "IS-IS reachability advertisement is malformed",
            "A recognized reachability TLV could not be consumed according to its declared prefix, neighbor, or sub-TLV boundaries.",
            tlvs=malformed_names,
        ))
    return rows


def _ldp_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if bool(fields.get("messages_truncated")):
        rows.append(_finding(
            "warning", "LDP_MESSAGE_VECTOR_TRUNCATED", "ldp", "LDP PDU message vector is incomplete",
            "The LDP PDU length and structurally decoded message boundaries did not consume the same bytes.",
            lsr_id=str(fields.get("lsr_id") or ""),
        ))
    messages = fields.get("messages") if isinstance(fields.get("messages"), list) else []
    if any(isinstance(row, Mapping) and str(row.get("type_name") or "") == "notification" for row in messages):
        rows.append(_finding(
            "warning", "LDP_NOTIFICATION", "ldp", "LDP Notification message observed",
            "An LDP peer emitted a Notification. Correlate the Status TLV and adjacent label/session events before assigning root cause.",
            lsr_id=str(fields.get("lsr_id") or ""),
        ))
    malformed_fec = False
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        tlvs = message.get("tlvs") if isinstance(message.get("tlvs"), list) else []
        if any(
            isinstance(tlv, Mapping) and str(tlv.get("name") or "") == "fec" and bool(tlv.get("malformed"))
            for tlv in tlvs
        ):
            malformed_fec = True
            break
    if malformed_fec:
        rows.append(_finding(
            "warning", "LDP_FEC_MALFORMED", "ldp", "LDP FEC element vector is malformed",
            "A recognized FEC TLV ended before its declared address-family/prefix encoding could be consumed.",
            lsr_id=str(fields.get("lsr_id") or ""),
        ))
    return rows




def _dhcp_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if bool(fields.get("options_malformed")):
        rows.append(_finding(
            "warning", "DHCP_OPTIONS_MALFORMED", "dhcp", "DHCP option vector is malformed",
            "A DHCP option length exceeded the available message boundary.",
            message_type_name=str(fields.get("message_type_name") or ""),
        ))
    if str(fields.get("message_type_name") or "") == "nak":
        rows.append(_finding(
            "note", "DHCP_NAK_OBSERVED", "dhcp", "DHCP negative acknowledgement observed",
            "A DHCP server rejected a requested lease. Correlate transaction ID, server identifier, and surrounding Discover/Offer/Request traffic.",
            transaction_id=int(fields.get("transaction_id") or 0),
        ))
    return rows


def _dhcpv6_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if bool(fields.get("options_malformed")):
        rows.append(_finding(
            "warning", "DHCPV6_OPTIONS_MALFORMED", "dhcpv6", "DHCPv6 option vector is malformed",
            "A DHCPv6 option or relay-encapsulated option ended outside the available message boundary.",
            message_type_name=str(fields.get("message_type_name") or ""),
        ))

    def status_codes(options: object, depth: int = 0) -> list[int]:
        if depth > 5 or not isinstance(options, list):
            return []
        values: list[int] = []
        for row in options[:256]:
            if not isinstance(row, Mapping):
                continue
            if str(row.get("name") or "") == "status-code":
                try:
                    values.append(int(row.get("status_code") or 0))
                except (TypeError, ValueError, OverflowError):
                    record_current_exception(__name__, '_dhcpv6_findings.status_codes:647')
            values.extend(status_codes(row.get("options"), depth + 1))
            message = row.get("message")
            if isinstance(message, Mapping):
                values.extend(status_codes(message.get("options"), depth + 1))
        return values[:64]

    failures = sorted({value for value in status_codes(fields.get("options")) if value != 0})
    if failures:
        rows.append(_finding(
            "note", "DHCPV6_FAILURE_STATUS", "dhcpv6", "DHCPv6 non-success status observed",
            "A DHCPv6 Status Code other than Success was observed. The status message itself is intentionally not retained.",
            status_codes=failures,
        ))
    return rows


def _radius_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if bool(fields.get("attributes_malformed")):
        rows.append(_finding(
            "warning", "RADIUS_ATTRIBUTES_MALFORMED", "radius", "RADIUS attribute vector is malformed",
            "A RADIUS attribute length was invalid or extended beyond the packet boundary.",
            code_name=str(fields.get("code_name") or ""),
        ))
    code_name = str(fields.get("code_name") or "")
    if code_name in {"access-reject", "access-challenge"}:
        rows.append(_finding(
            "note", "RADIUS_AUTH_OUTCOME", "radius", f"RADIUS {code_name.replace('-', ' ')} observed",
            "The authentication outcome is recorded without retaining user names, passwords, EAP payloads, or authenticators in plaintext.",
            code_name=code_name, identifier=int(fields.get("identifier") or 0),
        ))
    return rows


def _snmp_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if bool(fields.get("pdu_malformed")):
        rows.append(_finding(
            "warning", "SNMP_PDU_MALFORMED", "snmp", "SNMP PDU body is structurally incomplete",
            "The SNMP message and PDU type were identifiable, but the PDU body ended before mandatory request metadata could be decoded.",
            pdu_type=str(fields.get("pdu_type") or ""), pdu_error=str(fields.get("pdu_error") or ""),
        ))
    try:
        error_status = int(fields.get("error_status") or 0)
    except (TypeError, ValueError, OverflowError):
        error_status = 0
    if error_status:
        rows.append(_finding(
            "note", "SNMP_ERROR_STATUS", "snmp", "SNMP response carries a non-zero error status",
            "The response indicates an SNMP operation-level error; correlate the error index with the decoded variable-binding list.",
            error_status=error_status, error_index=int(fields.get("error_index") or 0),
        ))
    if str(fields.get("version_name") or "") == "v3" and bool(fields.get("privacy_flag")) and not bool(fields.get("auth_flag")):
        rows.append(_finding(
            "warning", "SNMPV3_PRIV_WITHOUT_AUTH", "snmp", "SNMPv3 privacy flag set without authentication flag",
            "SNMPv3 requires privacy to be accompanied by authentication; this flag combination is structurally invalid.",
        ))
    return rows


def _sctp_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    chunks = fields.get("chunks") if isinstance(fields.get("chunks"), list) else []
    if any(isinstance(chunk, Mapping) and str(chunk.get("name")) == "ABORT" for chunk in chunks):
        rows.append(_finding(
            "warning", "SCTP_ABORT", "sctp", "SCTP ABORT observed",
            "An SCTP association abort was observed. Correlate with INIT/COOKIE and endpoint logs before assigning a root cause.",
        ))
    if len(chunks) >= 64:
        rows.append(_finding(
            "note", "SCTP_CHUNK_BUDGET_REACHED", "sctp", "SCTP chunk analysis budget reached",
            "The frame contained at least the native per-packet chunk budget. External dissection can be used for additional chunks.",
            chunk_count=len(chunks),
        ))
    return rows




def _mpls_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    labels = fields.get("labels") if isinstance(fields.get("labels"), list) else []
    if bool(fields.get("label_budget_reached")):
        rows.append(_finding(
            "note", "MPLS_LABEL_BUDGET_REACHED", "mpls", "MPLS label-stack analysis budget reached",
            "No Bottom-of-Stack bit was observed before the bounded native label budget was exhausted.",
            decoded_labels=len(labels),
        ))
    for index, label in enumerate(labels):
        if not isinstance(label, Mapping):
            continue
        value = int(label.get("label") or 0)
        if value == 3:
            rows.append(_finding(
                "warning", "MPLS_IMPLICIT_NULL_ON_WIRE", "mpls", "MPLS Implicit NULL label observed on the wire",
                "Label value 3 is an Implicit NULL control-plane value and is not expected as a transmitted label-stack entry.",
                stack_index=index,
            ))
        if int(label.get("ttl") or 0) == 0:
            rows.append(_finding(
                "note", "MPLS_TTL_ZERO", "mpls", "MPLS label TTL is zero",
                "The label entry has no remaining TTL. Correlate ICMP/MPLS diagnostics and adjacent hops before assigning a forwarding fault.",
                stack_index=index, label=value,
            ))
        if value == 7 and index + 1 < len(labels):
            following = labels[index + 1] if isinstance(labels[index + 1], Mapping) else {}
            entropy = int(following.get("label") or 0)
            if entropy <= 15:
                rows.append(_finding(
                    "warning", "MPLS_ENTROPY_LABEL_RESERVED", "mpls", "Entropy Label uses special-purpose label space",
                    "The label following an Entropy Label Indicator is in the special-purpose range rather than a normal entropy-label value.",
                    stack_index=index + 1, label=entropy,
                ))
        if value == 15 and index + 1 < len(labels):
            extended = int((labels[index + 1] if isinstance(labels[index + 1], Mapping) else {}).get("label") or 0)
            if extended <= 15 and extended != 7:
                rows.append(_finding(
                    "warning", "MPLS_INVALID_EXTENDED_SPECIAL_PURPOSE", "mpls", "Invalid extended special-purpose label encoding",
                    "The Extension Label is followed by a value that is reserved by the extended special-purpose label rules.",
                    stack_index=index + 1, label=extended,
                ))
    return rows




def _vxlan_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if not bool(fields.get("instance_valid")):
        rows.append(_finding(
            "warning", "VXLAN_VNI_FLAG_MISSING", "vxlan", "VXLAN VNI valid flag is not set",
            "The VXLAN I flag is required for a valid VNI in the base VXLAN header.",
            vni=int(fields.get("vni") or 0),
        ))
    if int(fields.get("reserved_flag_bits") or 0) or bool(fields.get("reserved_bytes_nonzero")):
        rows.append(_finding(
            "note", "VXLAN_RESERVED_NONZERO", "vxlan", "VXLAN reserved fields are non-zero",
            "The base VXLAN format reserves all flag bits except I and requires reserved bytes to be zero on transmission.",
            reserved_flag_bits=int(fields.get("reserved_flag_bits") or 0),
        ))
    return rows


def _geneve_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if int(fields.get("version") or 0) != 0:
        rows.append(_finding(
            "warning", "GENEVE_VERSION_UNSUPPORTED", "geneve", "Geneve version is not version 0",
            "The native decoder recognizes the base format but this packet advertises a Geneve version outside the standardized version-0 format.",
            version=int(fields.get("version") or 0),
        ))
    if bool(fields.get("options_malformed")):
        rows.append(_finding(
            "warning", "GENEVE_OPTIONS_MALFORMED", "geneve", "Geneve option vector is malformed",
            "The sum of decoded Geneve option lengths did not match the base header Opt Len boundary.",
            option_length=int(fields.get("option_length") or 0),
        ))
    if int(fields.get("reserved_bits") or 0) or int(fields.get("reserved_byte") or 0):
        rows.append(_finding(
            "note", "GENEVE_RESERVED_NONZERO", "geneve", "Geneve reserved fields are non-zero",
            "Reserved Geneve base-header bits are expected to be zero on transmission.",
        ))
    return rows


def _modbus_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    if not bool(fields.get("exception")):
        return []
    return [_finding(
        "warning", "MODBUS_EXCEPTION_RESPONSE", "modbus-tcp", "Modbus exception response observed",
        "The response function code has the exception bit set. This is a protocol-level device/application error, not by itself evidence of compromise.",
        function_code=int(fields.get("function_code") or 0), exception_code=fields.get("exception_code"),
    )]


def _industrial_findings(protocol: str, fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    rows: list[ProtocolExpertFinding] = []
    if protocol == "dnp3" and fields.get("crc_verified") is False:
        rows.append(_finding(
            "info", "DNP3_CRC_NOT_VERIFIED_NATIVE", "dnp3", "DNP3 native metadata decoded without CRC verification",
            "The native fast path extracted bounded link/transport/application metadata but did not claim DNP3 block CRC validation. Use external deep dissection when CRC evidence is required.",
        ))
    if protocol == "iec104" and str(fields.get("frame_kind") or "") == "u" and str(fields.get("u_function") or "").startswith("0x"):
        rows.append(_finding(
            "note", "IEC104_UNKNOWN_U_FUNCTION", "iec104", "Unknown IEC 104 U-format control function",
            "The U-format control octet did not match the native decoder's standardized STARTDT/STOPDT/TESTFR controls.",
            u_function=str(fields.get("u_function") or ""),
        ))
    return rows


def _ssh_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    if str(fields.get("message") or "") != "KEXINIT":
        return []
    kex = {str(item).casefold() for item in fields.get("kex_algorithms", ()) if str(item)}
    host = {str(item).casefold() for item in fields.get("server_host_key_algorithms", ()) if str(item)}
    legacy_kex = sorted(kex & {"diffie-hellman-group1-sha1"})
    legacy_host = sorted(host & {"ssh-dss"})
    rows: list[ProtocolExpertFinding] = []
    if legacy_kex:
        rows.append(_finding(
            "note", "SSH_LEGACY_KEX_OFFERED", "ssh", "Legacy SSH key exchange offered",
            "KEXINIT advertised a legacy key-exchange algorithm. This is an offer, not proof that it was selected.",
            algorithms=legacy_kex,
        ))
    if legacy_host:
        rows.append(_finding(
            "note", "SSH_LEGACY_HOSTKEY_OFFERED", "ssh", "Legacy SSH host-key algorithm offered",
            "KEXINIT advertised a legacy host-key algorithm. Correlate both directions before inferring negotiation.",
            algorithms=legacy_host,
        ))
    return rows


def _srv6_findings(fields: Mapping[str, Any]) -> list[ProtocolExpertFinding]:
    if not bool(fields.get("segment_routing_header")):
        return []
    segments_left = int(fields.get("segments_left") or 0)
    last_entry = int(fields.get("last_entry") or 0)
    if segments_left > last_entry:
        return [_finding(
            "warning", "SRV6_SEGMENTS_LEFT_INVALID", "ipv6-routing", "SRv6 Segments Left exceeds Last Entry",
            "The Segment Routing Header carries a Segments Left value beyond the encoded segment-list boundary.",
            segments_left=segments_left, last_entry=last_entry,
        )]
    return []
