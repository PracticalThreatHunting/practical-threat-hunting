#!/usr/bin/env python3
"""Generate deterministic, file-only fixtures for Practical Threat Hunting Book 5.

The generator never opens a network socket.  Every address and domain is reserved
for documentation, private lab use, or special-use testing.  Suspicious labels
describe traffic *shape*, not an executable C2 or exfiltration implementation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import struct
import base64
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Scapy 2.6.1 is pinned and version-checked by the harness, but is intentionally
# not imported here.  On some offline Linux sandboxes ``scapy.all`` performs
# AF_NETLINK interface discovery during import.  The generator must make no
# socket call, so its deterministic packet writer uses only the standard
# library and produces identical bytes on every supported host.
SCAPY_IMPORT_ERROR = "not imported by design; deterministic stdlib writer avoids interface discovery"


ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "fixtures" / "generated"
RAW = GENERATED / "raw"
PCAP = ROOT / "fixtures" / "pcap"
MANIFESTS = ROOT / "fixtures" / "manifests"
GOLDEN = ROOT / "golden"
BASE = datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc)

FIELDS = [
    "event_id", "fixture_id", "case_id", "control", "source", "event_type",
    "ts", "ts_end", "sensor", "src_ip", "src_port", "dst_ip", "dst_port",
    "transport", "ip_proto", "direction", "direction_basis", "src_role",
    "dst_role", "src_segment", "dst_segment", "action", "outcome",
    "connection_state", "service", "app_proto", "channel", "query",
    "base_domain", "qtype", "rcode", "answer_count", "dns_label_length",
    "dns_label_entropy", "sequential_label", "method", "host", "authority",
    "uri", "status_code", "user_agent", "mime_type", "filename", "file_size",
    "file_hash", "sni", "alpn", "tls_version", "fingerprint", "cert_subject",
    "cert_issuer", "cert_valid_days", "cert_self_signed", "sni_cert_match",
    "ech_status", "quic_version", "proxy_method", "policy", "vpn_session_id",
    "assigned_ip", "route_mode", "mapping_state", "bytes_out", "bytes_in",
    "packets_out", "packets_in", "duration_s", "sample_rate", "counter_layer",
    "flow_complete", "parser_zeek", "parser_suricata", "correlation_key",
    "anomaly", "icmp_version", "icmp_type", "icmp_code", "payload_len",
    "icmp_id", "icmp_seq", "ip_protocol_number", "tunnel_type", "share_name",
    "rpc_operation", "remote_admin_proto", "coverage_state", "visibility_basis",
    "approved", "proxy_rewrite", "collection_interval", "note",
]

# Native producer paths used by the machine-checkable raw/canonical lineage
# map.  A path is encoded as ``record:<key>`` or
# ``record:<object>:<key>`` so producer keys containing dots stay unambiguous.
# Fields without an exact producer value are copied into the explicitly named
# adapter_enrichment object; they are never represented as native evidence.
_COMMON_NATIVE_PATHS = {
    "source": "envelope:producer",
}
_ZEEK_NATIVE_PATHS = {
    "ts": "record:ts", "src_ip": "record:id.orig_h",
    "src_port": "record:id.orig_p", "dst_ip": "record:id.resp_h",
    "dst_port": "record:id.resp_p", "transport": "record:proto",
    "service": "record:service", "app_proto": "record:service",
    "query": "record:query", "qtype": "record:qtype_name",
    "rcode": "record:rcode_name", "method": "record:method",
    "host": "record:host", "uri": "record:uri",
    "status_code": "record:status_code", "user_agent": "record:user_agent",
    "mime_type": "record:mime_type", "filename": "record:filename",
    "file_size": "record:file_size", "file_hash": "record:file_hash",
    "sni": "record:server_name", "alpn": "record:next_protocol",
    "bytes_out": "record:orig_bytes", "bytes_in": "record:resp_bytes",
    "duration_s": "record:duration", "parser_zeek": "record:parser_protocol",
    "correlation_key": "record:uid", "share_name": "record:share_name",
    "rpc_operation": "record:rpc_operation",
    "coverage_state": "record:coverage_state",
    "collection_interval": "record:collection_interval",
}
_SURICATA_NATIVE_PATHS = {
    "event_type": "record:event_type", "ts": "record:timestamp",
    "src_ip": "record:src_ip", "src_port": "record:src_port",
    "dst_ip": "record:dest_ip", "dst_port": "record:dest_port",
    "transport": "record:proto", "app_proto": "record:app_proto",
    "sni": "record:tls:sni", "alpn": "record:tls:alpn",
    "cert_subject": "record:tls:subject", "cert_issuer": "record:tls:issuerdn",
    "cert_valid_days": "record:tls:validity_days",
    "cert_self_signed": "record:tls:self_signed",
    "sni_cert_match": "record:tls:sni_cert_match",
    "bytes_out": "record:flow:bytes_toserver",
    "bytes_in": "record:flow:bytes_toclient",
    "parser_suricata": "record:parser_protocol",
    "correlation_key": "record:flow_id", "policy": "record:policy",
    "share_name": "record:smb:share",
    "rpc_operation": "record:smb:rpc_operation",
    "filename": "record:smb:filename", "file_size": "record:smb:file_size",
    "coverage_state": "record:coverage_state",
}
_IPFIX_NATIVE_PATHS = {
    "ts": "record:flowStartMilliseconds", "ts_end": "record:flowEndMilliseconds",
    "src_ip": "record:sourceIPv4Address", "src_port": "record:sourceTransportPort",
    "dst_ip": "record:destinationIPv4Address", "dst_port": "record:destinationTransportPort",
    "ip_protocol_number": "record:protocolIdentifier",
    "bytes_out": "record:octetDeltaCount", "bytes_in": "record:reverseOctetDeltaCount",
    "sample_rate": "record:samplingPacketInterval",
    "service": "record:applicationService", "app_proto": "record:applicationProtocol",
    "duration_s": "record:flowDurationSeconds", "flow_complete": "record:flowComplete",
    "counter_layer": "record:counterLayer", "coverage_state": "record:coverageState",
    "collection_interval": "record:collectionInterval",
}
_RESOLVER_NATIVE_PATHS = {
    "ts": "record:event_time", "src_ip": "record:client_ip",
    "dst_ip": "record:resolver_ip", "transport": "record:transport",
    "query": "record:query_name", "base_domain": "record:base_domain",
    "qtype": "record:qtype_name", "rcode": "record:rcode_name",
    "answer_count": "record:answer_count",
    "dns_label_length": "record:first_label_length",
    "dns_label_entropy": "record:first_label_entropy",
    "sequential_label": "record:sequential_label",
    "coverage_state": "record:coverage_state",
    "collection_interval": "record:collection_interval",
}
_PROXY_NATIVE_PATHS = {
    "ts": "record:event_time", "src_ip": "record:client_ip",
    "dst_ip": "record:server_ip", "dst_port": "record:server_port",
    "service": "record:service", "app_proto": "record:app_protocol",
    "channel": "record:channel", "sni": "record:tls_sni",
    "alpn": "record:negotiated_alpn", "method": "record:method",
    "authority": "record:authority", "uri": "record:uri",
    "status_code": "record:status", "policy": "record:policy_name",
    "action": "record:action", "outcome": "record:outcome",
    "visibility_basis": "record:visibility_basis",
    "bytes_out": "record:bytes_sent", "bytes_in": "record:bytes_received",
}
_FIREWALL_NATIVE_PATHS = {
    "ts": "record:event_time", "src_ip": "record:pre_nat_src_ip",
    "src_port": "record:pre_nat_src_port", "dst_ip": "record:destination_ip",
    "dst_port": "record:destination_port", "transport": "record:transport",
    "action": "record:action", "outcome": "record:outcome",
    "connection_state": "record:connection_state",
    "mapping_state": "record:nat_mapping_state", "policy": "record:policy_name",
    "ip_protocol_number": "record:ip_protocol_number",
    "bytes_out": "record:bytes_sent", "bytes_in": "record:bytes_received",
    "coverage_state": "record:coverage_state",
}
_FLOW_NATIVE_PATHS = {
    "ts": "record:event_time", "src_ip": "record:src", "src_port": "record:sport",
    "dst_ip": "record:dst", "dst_port": "record:dport", "action": "record:action",
    "outcome": "record:outcome", "service": "record:service",
    "bytes_out": "record:bytes_sent", "bytes_in": "record:bytes_received",
    "vpn_session_id": "record:session_id", "assigned_ip": "record:assigned_ip",
    "mapping_state": "record:mapping_state", "route_mode": "record:route_mode",
    "icmp_version": "record:icmp_version", "icmp_type": "record:icmp_type",
    "icmp_code": "record:icmp_code", "payload_len": "record:payload_len",
    "icmp_id": "record:icmp_id", "icmp_seq": "record:icmp_seq",
    "coverage_state": "record:coverage_state",
}


def analytic_fields_for_hunt(hunt: int) -> list[str]:
    """Return canonical input fields referenced by the published SQL listing."""
    sql = (ROOT / "queries" / f"hunt_{hunt:02d}.sql").read_text(encoding="utf-8")
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = re.sub(r"'(?:''|[^'])*'", "''", sql)
    return [field for field in FIELDS
            if re.search(rf"\b{re.escape(field)}\b", sql, flags=re.I)]


def _native_paths(producer: object) -> dict[str, str]:
    name = str(producer)
    paths = dict(_COMMON_NATIVE_PATHS)
    if name.startswith("zeek"):
        paths.update(_ZEEK_NATIVE_PATHS)
    elif name == "suricata":
        paths.update(_SURICATA_NATIVE_PATHS)
    elif name == "ipfix":
        paths.update(_IPFIX_NATIVE_PATHS)
    elif name == "resolver":
        paths.update(_RESOLVER_NATIVE_PATHS)
    elif name == "proxy":
        paths.update(_PROXY_NATIVE_PATHS)
    elif name == "firewall":
        paths.update(_FIREWALL_NATIVE_PATHS)
    elif name in {"vpn_flow", "eastwest_flow", "packet"}:
        paths.update(_FLOW_NATIVE_PATHS)
    return paths


def resolve_lineage_path(envelope: dict[str, object], path: str) -> object:
    """Resolve the deliberately small path vocabulary stored in raw wrappers."""
    parts = path.split(":")
    if parts == ["envelope", "producer"]:
        return envelope["producer"]
    if parts[0] == "adapter_enrichment" and len(parts) == 2:
        return dict(envelope["adapter_enrichment"])[parts[1]]
    if parts[0] == "record" and len(parts) >= 2:
        value: object = envelope["record"]
        for key in parts[1:]:
            value = dict(value)[key]
        return value
    raise KeyError(f"unsupported raw-lineage path: {path}")


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value: object) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def label_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value.lower())
    n = len(value)
    return round(-sum((v / n) * math.log2(v / n) for v in counts.values()), 5)


def event(hunt: int, case: str, control: str, source: str, event_type: str,
          when: datetime, **values: object) -> dict[str, object]:
    row: dict[str, object] = {key: None for key in FIELDS}
    row.update({
        "event_id": f"H{hunt:02d}-{case}-{values.pop('ordinal', 1):03d}",
        "fixture_id": f"B05-H{hunt:02d}-v1",
        "case_id": f"H{hunt:02d}-{case}",
        "control": control,
        "source": source,
        "event_type": event_type,
        "ts": iso(when),
        "sensor": "sensor-a",
        "transport": "tcp",
        "direction": "outbound",
        "direction_basis": "fixture-role-map",
        "src_role": "workstation",
        "dst_role": "external_service",
        "src_segment": "users",
        "dst_segment": "internet",
        "action": "allow",
        "outcome": "established",
        "connection_state": "complete",
        "counter_layer": "observed_ip",
        "flow_complete": True,
        "sample_rate": 1,
        "coverage_state": "complete",
        "visibility_basis": "metadata",
        "approved": False,
        "proxy_rewrite": False,
        "collection_interval": "present",
    })
    row.update(values)
    unknown = set(row) - set(FIELDS)
    if unknown:
        raise ValueError(f"unknown fixture fields: {sorted(unknown)}")
    return row


def timed_events(hunt: int, case: str, control: str, source: str, event_type: str,
                 start: datetime, offsets: list[int], **values: object) -> list[dict[str, object]]:
    rows = []
    for ordinal, seconds in enumerate(offsets, 1):
        per_row = {k: (v(ordinal) if callable(v) else v) for k, v in values.items()}
        rows.append(event(hunt, case, control, source, event_type,
                          start + timedelta(seconds=seconds), ordinal=ordinal, **per_row))
    return rows


def fixtures_01_08() -> dict[int, list[dict[str, object]]]:
    out: dict[int, list[dict[str, object]]] = {}

    out[1] = timed_events(
        1, "positive", "positive", "zeek_dns", "dns", BASE,
        [0, 2, 4, 7, 11], src_ip="10.50.1.10",
        src_port=lambda i: 53000 + i, dst_ip="203.0.113.53", dst_port=53,
        transport=lambda i: "tcp" if i == 5 else "udp",
        query=lambda i: f"bypass-{i}.portal.example", base_domain="portal.example",
        qtype=lambda i: "TXT" if i == 5 else ("AAAA" if i % 2 == 0 else "A"),
        rcode="NOERROR", answer_count=1, mapping_state="exact", approved=False,
        note="Established direct DNS exchange outside the role's resolver policy.")
    out[1] += timed_events(
        1, "negative", "negative", "zeek_dns", "dns", BASE,
        [1, 3, 5, 8, 12], src_ip="10.50.1.11",
        src_port=lambda i: 53100 + i, dst_ip="10.50.0.53", dst_port=53,
        transport=lambda i: "tcp" if i == 5 else "udp",
        query=lambda i: f"approved-{i}.updates.example", base_domain="updates.example",
        qtype=lambda i: "AAAA" if i % 2 == 0 else "A", rcode="NOERROR",
        answer_count=1, mapping_state="exact", approved=True,
        note="Approved recursive-resolver exchange.")
    out[1] += timed_events(
        1, "edge-denied", "edge", "firewall", "dns", BASE, [9, 10],
        src_ip="10.50.1.12", src_port=lambda i: 53200 + i,
        dst_ip="198.51.100.53", dst_port=53, transport=lambda i: "tcp" if i == 2 else "udp",
        action="deny", outcome="blocked", connection_state="attempt", query=None,
        mapping_state="exact", approved=False,
        note="A deny is an attempted path, not an established DNS exchange.")
    out[1] += timed_events(
        1, "edge-nat-collision", "edge", "firewall", "dns", BASE, [13, 13],
        src_ip="10.50.1.13", src_port=53300, dst_ip="192.0.2.53", dst_port=53,
        transport="udp", action="allow", outcome="unknown", connection_state="incomplete",
        query=None, mapping_state="ambiguous-nat-collision", coverage_state="partial",
        approved=False, note="Two source candidates collide after incomplete NAT correlation.")

    out[2] = []
    encrypted_paths = [
        ("doh", "https", "tcp", 443, "h2"),
        ("dot", "tls", "tcp", 853, "dot"),
        ("doq", "quic", "udp", 853, "doq"),
    ]
    for path_index, (app_proto, channel, transport, port, alpn) in enumerate(encrypted_paths):
        out[2] += timed_events(
            2, f"positive-{app_proto}", "positive", "proxy" if app_proto == "doh" else "suricata",
            "quic" if app_proto == "doq" else "tls", BASE + timedelta(seconds=path_index * 7),
            [0, 30, 60, 90], src_ip=f"10.50.2.{10 + path_index}",
            dst_ip=f"203.0.113.{80 + path_index}",
            dst_port=port, transport=transport, ip_proto=17 if transport == "udp" else 6,
            service="encrypted_dns", app_proto=app_proto, channel=channel,
            host="resolver-unapproved.example" if app_proto == "doh" else None,
            sni="resolver-unapproved.example", alpn=alpn, approved=False,
            policy="default-egress")
        out[2] += timed_events(
            2, f"negative-{app_proto}", "negative", "proxy" if app_proto == "doh" else "suricata",
            "quic" if app_proto == "doq" else "tls", BASE + timedelta(seconds=path_index * 7 + 3),
            [0, 30, 60, 90], src_ip=f"10.50.2.{20 + path_index}",
            dst_ip=f"198.51.100.{80 + path_index}",
            dst_port=port, transport=transport, ip_proto=17 if transport == "udp" else 6,
            service="encrypted_dns", app_proto=app_proto, channel=channel,
            host="resolver-approved.example" if app_proto == "doh" else None,
            sni="resolver-approved.example", alpn=alpn, approved=True,
            policy="approved-secure-dns")
    out[2] += timed_events(2, "negative-web", "negative", "zeek_ssl", "tls", BASE,
                           [8, 38, 68, 98], src_ip="10.50.2.30", dst_ip="198.51.100.90",
                           dst_port=443, service="web", app_proto="tls", channel="https",
                           sni="ordinary-web.example", alpn="h2", approved=True,
                           policy="default-web")
    out[2].append(event(2, "edge-ech", "edge", "suricata", "quic", BASE + timedelta(seconds=12),
                        src_ip="10.50.2.40", dst_ip="192.0.2.80", dst_port=443,
                        transport="udp", ip_proto=17, service="web", app_proto="quic",
                        channel="quic", ech_status="accepted-private-name-hidden",
                        sni=None, alpn="h3", approved=False,
                        note="Opaque QUIC alone does not establish encrypted DNS."))

    out[3] = []
    for i in range(200):
        # Thirty inert bytes encode to exactly 48 Base32 characters.  The final
        # two observations deliberately repeat prior labels: 200 observations,
        # 198 unique labels, and 6,000 bytes of theoretical pre-overhead
        # capacity.  These are data-shape fixtures, not an encoder or tunnel.
        label_index = i if i < 198 else i - 2
        inert = hashlib.sha256(f"book5-h03-{label_index:03d}".encode("ascii")).digest()[:30]
        label = base64.b32encode(inert).decode("ascii")
        out[3].append(event(3, "positive", "positive", "zeek_dns", "dns",
                            BASE + timedelta(seconds=i * 2), ordinal=i + 1,
                            src_ip="10.50.3.10", dst_ip="10.50.0.53", dst_port=53,
                            transport="udp", query=f"{label}.transfer.test", base_domain="transfer.test",
                            qtype="TXT", rcode="NOERROR", answer_count=1,
                            dns_label_length=len(label), dns_label_entropy=label_entropy(label),
                            bytes_out=90, bytes_in=60, approved=False))
        cdn = f"asset-{i:03d}-region-a"
        out[3].append(event(3, "negative", "negative", "zeek_dns", "dns",
                            BASE + timedelta(seconds=i * 3 + 1), ordinal=i + 1,
                            src_ip="10.50.3.11", dst_ip="10.50.0.53", dst_port=53,
                            transport="udp", query=f"{cdn}.cdn.example", base_domain="cdn.example",
                            qtype="A", rcode="NOERROR", answer_count=2,
                            dns_label_length=len(cdn), dns_label_entropy=label_entropy(cdn),
                            bytes_out=65, bytes_in=110, approved=True))
    dkim = "v=DKIM1"
    out[3].append(event(3, "edge-dkim", "edge", "resolver", "dns", BASE + timedelta(seconds=3),
                        src_ip="10.50.3.12", dst_ip="10.50.0.53", dst_port=53, transport="udp",
                        query="selector._domainkey.mail.example", base_domain="mail.example",
                        qtype="TXT", rcode="NOERROR", answer_count=1,
                        dns_label_length=len(dkim), dns_label_entropy=label_entropy(dkim),
                        bytes_out=72, bytes_in=240, approved=True))

    out[4] = []
    sparse_offsets = [0]
    for i in range(35):
        sparse_offsets.append(sparse_offsets[-1] + (23, 17, 20)[i % 3] * 60)
    out[4] += timed_events(4, "positive", "positive", "resolver", "dns", BASE,
                           sparse_offsets, src_ip="10.50.4.10", dst_ip="10.50.0.53",
                           dst_port=53, transport="udp", query=lambda i: f"node{i:04d}.quiet.test",
                           base_domain="quiet.test", qtype="A",
                           rcode=lambda i: "NXDOMAIN" if i <= 30 else "NOERROR",
                           answer_count=lambda i: 0 if i <= 30 else 1,
                           sequential_label=True, approved=False)
    reconnect_offsets = [burst * 4 * 3600 + item * 60 for burst in range(3) for item in range(12)]
    out[4] += timed_events(4, "negative", "negative", "resolver", "dns", BASE,
                           reconnect_offsets, src_ip="10.50.4.11", dst_ip="10.50.0.53",
                           dst_port=53, transport="udp", query=lambda i: f"printer-{i}.corp.invalid",
                           base_domain="corp.invalid", qtype="A", rcode="NXDOMAIN", answer_count=0,
                           sequential_label=False, approved=True, note="Search-suffix leakage control.")
    gap_observed_offsets = [seconds for seconds in sparse_offsets
                            if not (4 * 3600 <= seconds < 8 * 3600)]
    out[4] += timed_events(4, "edge-gap", "edge", "resolver", "dns", BASE,
                           gap_observed_offsets, src_ip="10.50.4.12", dst_ip="10.50.0.53",
                           dst_port=53, transport="udp", query=lambda i: f"edge{i:04d}.gap.test",
                           base_domain="gap.test", qtype="A",
                           rcode=lambda i: "NXDOMAIN" if i <= 20 else "NOERROR",
                           answer_count=lambda i: 0 if i <= 20 else 1,
                           sequential_label=True, coverage_state="partial",
                           collection_interval="four-hour-null-gap", approved=False,
                           note="Observed portions bracket a deterministic four-hour collection outage.")

    out[5] = []
    out[5] += timed_events(5, "positive", "positive", "zeek_http", "http", BASE,
                           [i * 45 for i in range(12)], src_ip="10.50.5.10", dst_ip="203.0.113.25",
                           dst_port=80, method="POST", host="sync.test", authority="sync.test",
                           uri="/api/sync", status_code=200, mime_type="application/octet-stream",
                           user_agent="Book5Fixture/1.0", bytes_out=96, bytes_in=112, approved=False,
                           visibility_basis="plaintext-http")
    for i in range(12):
        out[5].append(event(5, "negative", "negative", "proxy", "http", BASE + timedelta(seconds=i * 47),
                            ordinal=i + 1, src_ip="10.50.5.11", dst_ip="198.51.100.25", dst_port=443,
                            method="GET" if i % 3 else "POST", host="api.example", authority="api.example",
                            uri=f"/v1/items/{i}", status_code=200 + (i % 3), mime_type="application/json",
                            user_agent="ApprovedClient/4.2", bytes_out=80 + i * 17,
                            bytes_in=300 + i * 83, approved=True, visibility_basis="lawful-proxy-decryption"))
    out[5] += timed_events(5, "edge-health", "edge", "zeek_http", "http", BASE,
                           [i * 30 for i in range(10)], src_ip="10.50.5.12", dst_ip="192.0.2.25",
                           dst_port=80, method="GET", host="health.example", authority="health.example",
                           uri="/health", status_code=200, mime_type="text/plain", bytes_out=0,
                           bytes_in=2, approved=True, visibility_basis="plaintext-http")

    pos_offsets = [0, 58, 121, 179, 241, 298, 361, 421, 478, 540, 603, 661, 721, 779, 842, 899]
    neg_offsets = [0, 17, 91, 228, 246, 501, 509, 900, 1011, 1440, 1451, 2110, 2600]
    edge_offsets = [0, 60, 120, 240, 300, 420, 480, 600, 660, 780, 840, 960]
    out[6] = timed_events(6, "positive", "positive", "zeek_conn", "flow", BASE, pos_offsets,
                          src_ip="10.50.6.10", dst_ip="203.0.113.60", dst_port=443,
                          service="tls", app_proto="tls", channel="https", bytes_out=180,
                          bytes_in=220, duration_s=1.4, approved=False)
    out[6] += timed_events(6, "negative", "negative", "zeek_conn", "flow", BASE, neg_offsets,
                           src_ip="10.50.6.11", dst_ip="198.51.100.60", dst_port=443,
                           service="tls", app_proto="tls", channel="https", bytes_out=250,
                           bytes_in=900, duration_s=2.1, approved=False)
    out[6] += timed_events(6, "edge-missing", "edge", "zeek_conn", "flow", BASE, edge_offsets,
                           src_ip="10.50.6.12", dst_ip="192.0.2.60", dst_port=443,
                           service="tls", app_proto="tls", channel="https", bytes_out=180,
                           bytes_in=220, duration_s=1.4, coverage_state="partial",
                           collection_interval="missing-events", approved=False)

    out[7] = []
    for host_n in range(3):
        out[7] += timed_events(7, f"positive-host-{host_n + 1}", "positive", "ipfix", "flow",
                               BASE + timedelta(seconds=host_n * 4), [i * 300 for i in range(8)],
                               src_ip=f"10.50.7.{10 + host_n}", dst_ip="203.0.113.70", dst_port=443,
                               service="tls", app_proto="tls", bytes_out=210 + host_n * 4,
                               bytes_in=190 + host_n * 3, duration_s=1.2, approved=False)
    for host_n in range(8):
        out[7] += timed_events(7, f"negative-host-{host_n + 1}", "negative", "ipfix", "flow",
                               BASE + timedelta(seconds=host_n * 9), [i * 300 for i in range(8)],
                               src_ip=f"10.50.7.{30 + host_n}", dst_ip="198.51.100.70", dst_port=443,
                               service="tls", app_proto="tls", bytes_out=400,
                               bytes_in=120000, duration_s=4.0, approved=True)
    out[7] += timed_events(7, "edge-lb", "edge", "ipfix", "flow", BASE,
                           [i * 300 for i in range(8)], src_ip="10.50.7.50",
                           dst_ip=lambda i: f"192.0.2.{70 + (i % 3)}", dst_port=443,
                           service="tls", app_proto="tls", bytes_out=210, bytes_in=190,
                           duration_s=1.2, approved=True)

    out[8] = [
        event(8, "positive", "positive", "suricata", "tls", BASE,
              src_ip="10.50.8.10", dst_ip="203.0.113.81", dst_port=443, app_proto="tls",
              sni="billing.example", alpn="unknown/1", tls_version="TLSv1.3",
              fingerprint="t13d1516h2_8daaf6152771_02713d6af862", cert_subject="CN=printer.invalid",
              cert_issuer="CN=printer.invalid", cert_valid_days=3650, cert_self_signed=True,
              sni_cert_match=False, approved=False),
        event(8, "negative", "negative", "zeek_ssl", "tls", BASE + timedelta(seconds=2),
              src_ip="10.50.8.11", dst_ip="198.51.100.81", dst_port=443, app_proto="tls",
              sni="service.example", alpn="h2", tls_version="TLSv1.3",
              fingerprint="common-fixture-value", cert_subject="CN=service.example",
              cert_issuer="CN=Example Test CA", cert_valid_days=90, cert_self_signed=False,
              sni_cert_match=True, approved=True),
        event(8, "edge-intercept", "edge", "proxy", "tls", BASE + timedelta(seconds=4),
              src_ip="10.50.8.12", dst_ip="192.0.2.81", dst_port=443, app_proto="tls",
              sni="external.example", alpn="h2", tls_version="TLSv1.3",
              fingerprint="enterprise-proxy-fixture", cert_subject="CN=external.example",
              cert_issuer="CN=Enterprise Inspection Test CA", cert_valid_days=7,
              cert_self_signed=False, sni_cert_match=True, approved=True,
              policy="approved-tls-inspection", note="Short-lived enterprise interception certificate."),
    ]
    return out


def fixtures_09_16() -> dict[int, list[dict[str, object]]]:
    out: dict[int, list[dict[str, object]]] = {}

    out[9] = []
    out[9] += timed_events(9, "positive", "positive", "suricata", "quic", BASE,
                           [0, 60, 120, 180], src_ip="10.50.9.10", dst_ip="203.0.113.90",
                           dst_port=443, transport="udp", ip_proto=17, app_proto="quic",
                           service="http3", channel="quic", alpn="h3", quic_version="1",
                           ech_status="not_observed", approved=False)
    out[9].append(event(9, "positive", "positive", "firewall", "flow", BASE + timedelta(seconds=185),
                        ordinal=5, src_ip="10.50.9.10", dst_ip="203.0.113.90", dst_port=443,
                        transport="tcp", app_proto="tls", service="https", channel="https",
                        bytes_out=300, bytes_in=1200, duration_s=4, approved=False,
                        note="TCP fallback after QUIC attempts."))
    out[9] += timed_events(9, "negative", "negative", "suricata", "quic", BASE,
                           [5, 65, 125, 185], src_ip="10.50.9.11", dst_ip="198.51.100.90",
                           dst_port=443, transport="udp", ip_proto=17, app_proto="quic",
                           service="http3", channel="quic", alpn="h3", quic_version="1",
                           approved=True, policy="approved-browser-http3")
    out[9].append(event(9, "edge-ech", "edge", "zeek_quic", "quic", BASE + timedelta(seconds=10),
                        src_ip="10.50.9.12", dst_ip="192.0.2.90", dst_port=443, transport="udp",
                        ip_proto=17, app_proto="quic", service="http3", channel="quic", alpn="h3",
                        quic_version="1", ech_status="accepted-private-name-hidden", sni=None,
                        approved=True, note="ECH changes visibility; it is not itself a threat signal."))

    out[10] = [
        event(10, "positive", "positive", "proxy", "http", BASE,
              src_ip="10.50.10.10", dst_ip="203.0.113.100", dst_port=443,
              app_proto="http2", service="https", sni="outer.example", authority="inner.test",
              host="inner.test", method="POST", uri="/sync", status_code=200,
              visibility_basis="lawful-proxy-decryption", proxy_rewrite=False, approved=False),
        event(10, "negative", "negative", "proxy", "http", BASE + timedelta(seconds=1),
              src_ip="10.50.10.11", dst_ip="198.51.100.100", dst_port=443,
              app_proto="http2", service="https", sni="api.example", authority="api.example",
              host="api.example", method="GET", uri="/v1", status_code=200,
              visibility_basis="lawful-proxy-decryption", proxy_rewrite=False, approved=True),
        event(10, "edge-rewrite", "edge", "proxy", "http", BASE + timedelta(seconds=2),
              src_ip="10.50.10.12", dst_ip="192.0.2.100", dst_port=443,
              app_proto="http2", service="https", sni="edge.example", authority="origin.internal",
              host="origin.internal", method="GET", uri="/", status_code=200,
              visibility_basis="lawful-proxy-decryption", proxy_rewrite=True, approved=True),
        event(10, "edge-opaque", "edge", "zeek_ssl", "tls", BASE + timedelta(seconds=3),
              src_ip="10.50.10.13", dst_ip="192.0.2.101", dst_port=443,
              app_proto="tls", service="https", sni="outer.example", authority=None,
              visibility_basis="tls-metadata-only", approved=False,
              note="Without HTTP authority this sensor cannot test a mismatch."),
    ]

    out[11] = [
        event(11, "positive", "positive", "proxy", "proxy_session", BASE,
              ts_end=iso(BASE + timedelta(seconds=3600)), src_ip="10.50.11.10",
              dst_ip="203.0.113.111", dst_port=443, proxy_method="CONNECT",
              method="CONNECT", authority="relay.test:443", service="proxy_tunnel",
              duration_s=3600, bytes_out=18000, bytes_in=22000, approved=False),
        event(11, "negative", "negative", "proxy", "proxy_session", BASE + timedelta(seconds=10),
              ts_end=iso(BASE + timedelta(seconds=1900)), src_ip="10.50.11.11",
              dst_ip="198.51.100.111", dst_port=443, proxy_method="CONNECT",
              method="CONNECT", authority="support.example:443", service="remote_support",
              duration_s=1890, bytes_out=600000, bytes_in=900000, approved=True,
              policy="approved-remote-support"),
        event(11, "edge-denied", "edge", "proxy", "proxy_session", BASE + timedelta(seconds=20),
              src_ip="10.50.11.12", dst_ip="192.0.2.111", dst_port=443,
              proxy_method="CONNECT", method="CONNECT", authority="blocked.test:443",
              service="proxy_tunnel", duration_s=0, bytes_out=0, bytes_in=0,
              action="deny", outcome="blocked", connection_state="attempt", approved=False),
    ]

    out[12] = [
        event(12, "positive", "positive", "zeek", "parser_observation", BASE,
              src_ip="10.50.12.10", src_port=50122, dst_ip="203.0.113.122", dst_port=443,
              service="ssh", app_proto="ssh", parser_zeek="ssh", parser_suricata=None,
              correlation_key="1:h12-positive-ssh443", coverage_state="complete",
              note="Zeek identifies packet-backed SSH on the policy-unexpected TCP/443 path."),
        event(12, "positive", "positive", "suricata", "parser_observation", BASE + timedelta(milliseconds=5),
              ordinal=2, src_ip="10.50.12.10", src_port=50122, dst_ip="203.0.113.122", dst_port=443,
              service="ssh", app_proto="ssh", parser_zeek=None, parser_suricata="ssh",
              correlation_key="1:h12-positive-ssh443", coverage_state="complete",
              note="Suricata independently identifies packet-backed SSH on the same tuple."),
        event(12, "negative", "negative", "zeek", "parser_observation", BASE + timedelta(seconds=1),
              src_ip="10.50.12.11", src_port=50121, dst_ip="198.51.100.120", dst_port=8080,
              service="http", app_proto="http", parser_zeek="http",
              correlation_key="1:h12-negative-http8080", coverage_state="complete",
              policy="approved-nonstandard-http"),
        event(12, "negative", "negative", "suricata", "parser_observation", BASE + timedelta(seconds=1, milliseconds=5),
              ordinal=2, src_ip="10.50.12.11", src_port=50121, dst_ip="198.51.100.120", dst_port=8080,
              service="http", app_proto="http", parser_suricata="http",
              correlation_key="1:h12-negative-http8080", coverage_state="complete",
              policy="approved-nonstandard-http"),
        event(12, "edge-truncated", "edge", "zeek", "parser_observation", BASE + timedelta(seconds=2),
              src_ip="10.50.12.12", src_port=50122, dst_ip="192.0.2.120", dst_port=4443,
              parser_zeek="unknown", correlation_key="1:h12-edge-truncated", coverage_state="partial",
              collection_interval="truncated-pcap"),
        event(12, "edge-truncated", "edge", "suricata", "parser_observation", BASE + timedelta(seconds=2, milliseconds=5),
              ordinal=2, src_ip="10.50.12.12", src_port=50122, dst_ip="192.0.2.120", dst_port=4443,
              parser_suricata="tls", correlation_key="1:h12-edge-truncated", coverage_state="partial",
              collection_interval="truncated-pcap"),
    ]

    out[13] = [
        event(13, "positive", "positive", "ipfix", "flow", BASE,
              ts_end=iso(BASE + timedelta(hours=4)), src_ip="10.50.13.10",
              dst_ip="203.0.113.130", dst_port=443, service="tls", duration_s=14400,
              bytes_out=7200, bytes_in=9000, packets_out=120, packets_in=140,
              flow_complete=True, approved=False),
        event(13, "negative", "negative", "ipfix", "flow", BASE + timedelta(seconds=1),
              ts_end=iso(BASE + timedelta(hours=8)), src_ip="10.50.13.11",
              dst_ip="198.51.100.130", dst_port=5671, service="message_broker", duration_s=28799,
              bytes_out=8000, bytes_in=8200, packets_out=200, packets_in=205,
              flow_complete=True, approved=True),
        event(13, "edge-oneway", "edge", "ipfix", "flow", BASE + timedelta(seconds=2),
              ts_end=iso(BASE + timedelta(hours=3)), src_ip="10.50.13.12",
              dst_ip="192.0.2.130", dst_port=443, service="push_keepalive", duration_s=10798,
              bytes_out=5000, bytes_in=40, packets_out=100, packets_in=2,
              flow_complete=True, approved=False),
        event(13, "edge-timeout", "edge", "ipfix", "flow", BASE + timedelta(seconds=3),
              src_ip="10.50.13.13", dst_ip="192.0.2.131", dst_port=443,
              service="tls", duration_s=3600, bytes_out=3000, bytes_in=3100,
              flow_complete=False, connection_state="active-timeout", approved=False),
    ]
    for i, duration in enumerate((600, 900, 1200, 1800, 2400, 3600), 1):
        start = BASE + timedelta(seconds=10 + i)
        out[13].append(event(
            13, "negative-tls-cohort", "negative", "ipfix", "flow", start, ordinal=i,
            ts_end=iso(start + timedelta(seconds=duration)), src_ip=f"10.50.13.{20 + i}",
            dst_ip="198.51.100.132", dst_port=443, service="tls", app_proto="tls",
            duration_s=duration, bytes_out=duration * (400 + i * 20),
            bytes_in=duration * (600 + i * 25), packets_out=100 + i * 10,
            packets_in=130 + i * 10, flow_complete=True, approved=True,
            policy="approved-web-transfer"))

    out[14] = []
    out[14] += timed_events(14, "positive", "positive", "packet", "icmp", BASE,
                            [i * 2 for i in range(10)], src_ip="10.50.14.10", dst_ip="203.0.113.140",
                            transport="icmp", ip_proto=1, ip_protocol_number=1, icmp_version=4,
                            icmp_type=8, icmp_code=0, payload_len=256, icmp_id=1400,
                            icmp_seq=lambda i: i, approved=False)
    out[14] += timed_events(14, "negative", "negative", "packet", "icmp", BASE,
                            [i * 30 for i in range(8)], src_ip="2001:db8:14::10", dst_ip="ff02::1:ff00:1",
                            transport="icmpv6", ip_proto=58, ip_protocol_number=58, icmp_version=6,
                            icmp_type=135, icmp_code=0, payload_len=24, approved=True,
                            note="Essential IPv6 neighbor discovery control.")
    out[14] += timed_events(14, "edge-monitor", "edge", "packet", "icmp", BASE,
                            [i * 5 for i in range(10)], src_ip="10.50.14.20", dst_ip="192.0.2.140",
                            transport="icmp", ip_proto=1, ip_protocol_number=1, icmp_version=4,
                            icmp_type=8, icmp_code=0, payload_len=512, icmp_id=1410,
                            icmp_seq=lambda i: i, approved=True, policy="approved-monitoring")

    out[15] = [
        event(15, "positive", "positive", "firewall", "network_layer", BASE,
              src_ip="10.50.15.10", dst_ip="203.0.113.150", transport="ip",
              ip_proto=47, ip_protocol_number=47, tunnel_type="GRE", bytes_out=50000,
              bytes_in=1200, approved=False),
        event(15, "negative", "negative", "firewall", "network_layer", BASE + timedelta(seconds=1),
              src_ip="10.50.15.1", dst_ip="198.51.100.150", transport="ip",
              ip_proto=47, ip_protocol_number=47, tunnel_type="GRE", bytes_out=800000,
              bytes_in=790000, src_role="sdwan_gateway", approved=True,
              policy="approved-wan-overlay"),
        event(15, "edge-exporter", "edge", "ipfix", "network_layer", BASE + timedelta(seconds=2),
              src_ip="10.50.15.12", dst_ip="192.0.2.150", transport="ip",
              ip_proto=None, ip_protocol_number=None, tunnel_type=None,
              coverage_state="unsupported-field", approved=False,
              note="Exporter template omitted protocol number; absence is not protocol 0."),
    ]

    out[16] = [
        event(16, "positive", "positive", "zeek_ssh", "ssh", BASE,
              ts_end=iso(BASE + timedelta(seconds=1800)), src_ip="10.50.16.10",
              dst_ip="203.0.113.160", dst_port=22, service="ssh", app_proto="ssh",
              channel="ssh", duration_s=1800, bytes_out=24000, bytes_in=19000,
              approved=False, note="Passive shape cannot establish port forwarding."),
        event(16, "negative", "negative", "zeek_ssh", "ssh", BASE + timedelta(seconds=1),
              src_ip="10.50.16.11", dst_ip="198.51.100.160", dst_port=22,
              service="ssh", app_proto="ssh", channel="ssh", duration_s=44,
              bytes_out=3000, bytes_in=120000, approved=True, policy="approved-git-hosting"),
        event(16, "edge-incomplete", "edge", "firewall", "ssh", BASE + timedelta(seconds=2),
              src_ip="10.50.16.12", dst_ip="192.0.2.160", dst_port=22,
              service="ssh", app_proto="ssh", channel="ssh", duration_s=0,
              bytes_out=60, bytes_in=0, outcome="unknown", connection_state="incomplete",
              flow_complete=False, coverage_state="partial", approved=False),
    ]
    return out


def fixtures_17_24() -> dict[int, list[dict[str, object]]]:
    out: dict[int, list[dict[str, object]]] = {}

    out[17] = [
        event(17, "positive", "positive", "firewall", "channel_event", BASE,
              src_ip="10.50.17.10", dst_ip="203.0.113.170", dst_port=53, transport="udp",
              channel="dns", correlation_key="svc-switch.test", action="deny", outcome="blocked"),
        event(17, "positive", "positive", "proxy", "channel_event", BASE + timedelta(seconds=45),
              ordinal=2, src_ip="10.50.17.10", dst_ip="203.0.113.170", dst_port=443,
              channel="https", correlation_key="svc-switch.test", action="deny", outcome="blocked"),
        event(17, "positive", "positive", "suricata", "channel_event", BASE + timedelta(seconds=90),
              ordinal=3, src_ip="10.50.17.10", dst_ip="203.0.113.170", dst_port=443, transport="udp",
              channel="quic", app_proto="quic", correlation_key="svc-switch.test",
              action="allow", outcome="established", approved=False),
        event(17, "negative", "negative", "resolver", "channel_event", BASE + timedelta(seconds=2),
              src_ip="10.50.17.11", dst_ip="10.50.0.53", dst_port=53, transport="udp",
              channel="dns", correlation_key="unrelated-a.example", approved=True),
        event(17, "negative", "negative", "proxy", "channel_event", BASE + timedelta(seconds=20),
              ordinal=2, src_ip="10.50.17.11", dst_ip="198.51.100.171", dst_port=443,
              channel="https", correlation_key="unrelated-b.example", approved=False),
        event(17, "negative", "negative", "suricata", "channel_event", BASE + timedelta(seconds=40),
              ordinal=3, src_ip="10.50.17.11", dst_ip="192.0.2.171", dst_port=443, transport="udp",
              channel="quic", correlation_key="unrelated-c.example", approved=False),
        event(17, "edge-browser", "edge", "firewall", "channel_event", BASE + timedelta(seconds=5),
              src_ip="10.50.17.12", dst_ip="198.51.100.172", dst_port=443, transport="udp",
              channel="quic", correlation_key="browser-fallback.example", action="deny",
              outcome="blocked", approved=True),
        event(17, "edge-browser", "edge", "proxy", "channel_event", BASE + timedelta(seconds=7),
              ordinal=2, src_ip="10.50.17.12", dst_ip="198.51.100.172", dst_port=443,
              channel="https", correlation_key="browser-fallback.example", action="allow",
              outcome="established", approved=True),
    ]

    out[18] = []
    for i in range(25):
        out[18].append(event(18, "positive", "positive", "eastwest_flow", "flow",
                             BASE + timedelta(seconds=i * 20), ordinal=i + 1,
                             src_ip="10.50.18.10", dst_ip=f"10.60.1.{10 + i}",
                             dst_port=[22, 445, 3389, 5985][i % 4], dst_segment="servers",
                             dst_role="server", direction="east-west", action="deny" if i < 20 else "allow",
                             outcome="blocked" if i < 20 else "established",
                             connection_state="attempt" if i < 20 else "complete", approved=False))
        out[18].append(event(18, "negative", "negative", "eastwest_flow", "flow",
                             BASE + timedelta(seconds=i * 21), ordinal=i + 1,
                             src_ip="10.50.18.20", src_role="vulnerability_scanner",
                             dst_ip=f"10.60.2.{10 + i}", dst_port=[22, 80, 443, 445][i % 4],
                             dst_segment="servers", dst_role="server", direction="east-west",
                             action="deny" if i < 18 else "allow",
                             outcome="blocked" if i < 18 else "established", approved=True,
                             policy="approved-scanner"))
    out[18].append(event(18, "edge-lb", "edge", "eastwest_flow", "flow", BASE,
                         src_ip="10.50.18.30", src_role="load_balancer", dst_ip="10.60.3.10",
                         dst_port=443, dst_segment="servers", dst_role="web_server",
                         direction="east-west", approved=True))

    out[19] = []
    for i in range(6):
        out[19].append(event(19, "positive", "positive", "zeek_smb", "smb", BASE + timedelta(seconds=i * 30),
                             ordinal=i + 1, src_ip="10.50.19.10", dst_ip=f"10.60.19.{20 + i}",
                             dst_port=445, dst_segment="servers", dst_role="server", direction="east-west",
                             service="smb", app_proto="smb", share_name="ADMIN$",
                             rpc_operation="svcctl.CreateServiceW", filename="stager.bin",
                             mime_type="application/octet-stream", file_size=4096, approved=False))
        out[19].append(event(19, "negative", "negative", "suricata", "smb", BASE + timedelta(seconds=i * 35),
                             ordinal=i + 1, src_ip="10.50.19.20", src_role="deployment_server",
                             dst_ip=f"10.60.19.{40 + i}", dst_port=445, dst_segment="servers",
                             dst_role="server", direction="east-west", service="smb", app_proto="smb",
                             share_name="ADMIN$", rpc_operation="svcctl.CreateServiceW",
                             filename="approved-package.bin", mime_type="application/octet-stream",
                             file_size=8192, approved=True, policy="approved-software-deployment"))
    out[19].append(event(19, "edge-fileserver", "edge", "zeek_smb", "smb", BASE + timedelta(seconds=7),
                         src_ip="10.50.19.30", src_role="file_server", dst_ip="10.60.19.90",
                         dst_port=445, dst_segment="servers", dst_role="file_server",
                         direction="east-west", service="smb", app_proto="smb", share_name="DATA",
                         filename="quarterly.txt", file_size=1024, approved=True))

    out[20] = [
        event(20, "positive", "positive", "eastwest_flow", "remote_admin", BASE,
              src_ip="10.50.20.10", src_role="workstation", dst_ip="10.50.20.99",
              dst_role="workstation", dst_port=3389, direction="east-west",
              service="rdp", app_proto="rdp", remote_admin_proto="rdp", duration_s=900,
              bytes_out=800000, bytes_in=1200000, approved=False),
        event(20, "negative", "negative", "eastwest_flow", "remote_admin", BASE + timedelta(seconds=1),
              src_ip="10.50.20.20", src_role="jump_host", dst_ip="10.60.20.20",
              dst_role="server", dst_port=3389, direction="east-west", service="rdp",
              app_proto="rdp", remote_admin_proto="rdp", duration_s=1200,
              bytes_out=900000, bytes_in=1500000, approved=True, policy="approved-jump-path"),
        event(20, "edge-helpdesk", "edge", "firewall", "remote_admin", BASE + timedelta(hours=2),
              src_ip="10.50.20.30", src_role="helpdesk", dst_ip="10.50.20.31",
              dst_role="workstation", dst_port=5900, direction="east-west", service="vnc",
              app_proto="vnc", remote_admin_proto="vnc", duration_s=600,
              bytes_out=400000, bytes_in=700000, approved=True, policy="approved-support-window"),
    ]

    out[21] = []
    for i in range(15):
        out[21].append(event(21, "positive", "positive", "vpn_flow", "flow",
                             BASE + timedelta(seconds=60 + i * 15), ordinal=i + 1,
                             src_ip="10.250.21.10", assigned_ip="10.250.21.10",
                             dst_ip=f"10.60.21.{10 + i}", dst_port=445 if i % 2 else 3389,
                             direction="east-west", src_segment="vpn", dst_segment="servers",
                             dst_role="server", vpn_session_id="vpn-positive-1",
                             mapping_state="exact", route_mode="full-tunnel", approved=False))
    for i in range(4):
        out[21].append(event(21, "negative", "negative", "vpn_flow", "flow",
                             BASE + timedelta(seconds=90 + i * 30), ordinal=i + 1,
                             src_ip="10.250.21.20", assigned_ip="10.250.21.20",
                             dst_ip=f"10.60.21.{50 + i}", dst_port=22, direction="east-west",
                             src_segment="vpn", dst_segment="servers", dst_role="server",
                             vpn_session_id="vpn-negative-1", mapping_state="exact",
                             route_mode="full-tunnel", approved=True, policy="approved-vpn-admin"))
    for i in range(15):
        out[21].append(event(21, "edge-reuse", "edge", "vpn_flow", "flow",
                             BASE + timedelta(seconds=120 + i * 15), ordinal=i + 1,
                             src_ip="10.250.21.30", assigned_ip="10.250.21.30",
                             dst_ip=f"10.60.21.{70 + i}", dst_port=445, direction="east-west",
                             src_segment="vpn", dst_segment="servers", dst_role="server",
                             vpn_session_id=None, mapping_state="ambiguous-pool-reuse",
                             route_mode="unknown", approved=False))

    out[22] = [
        event(22, "positive", "positive", "zeek_files", "file", BASE,
              src_ip="203.0.113.220", src_role="external_service", src_segment="internet",
              dst_ip="10.50.22.10", dst_role="workstation", dst_segment="users",
              direction="inbound", service="http", app_proto="http", filename="invoice.pdf.exe",
              mime_type="application/x-dosexec", file_size=24576,
              file_hash=hashlib.sha256(b"BOOK5-BENIGN-DUMMY-EXECUTABLE-SHAPE").hexdigest(),
              visibility_basis="plaintext-file-metadata", approved=False),
        event(22, "negative", "negative", "proxy", "file", BASE + timedelta(seconds=1),
              src_ip="198.51.100.220", src_role="software_repository", src_segment="internet",
              dst_ip="10.50.22.11", dst_role="developer", dst_segment="engineering",
              direction="inbound", service="https", app_proto="http2", filename="sdk.tar.gz",
              mime_type="application/gzip", file_size=24000000,
              file_hash=hashlib.sha256(b"BOOK5-BENIGN-PACKAGE").hexdigest(),
              visibility_basis="lawful-proxy-decryption", approved=True,
              policy="approved-development-repository"),
        event(22, "edge-encrypted", "edge", "zeek_ssl", "file", BASE + timedelta(seconds=2),
              src_ip="192.0.2.220", src_role="external_service", src_segment="internet",
              dst_ip="10.50.22.12", dst_role="workstation", dst_segment="users",
              direction="inbound", service="https", app_proto="tls", filename=None,
              mime_type=None, file_size=None, file_hash=None, visibility_basis="tls-metadata-only",
              coverage_state="content-encrypted", approved=False),
    ]

    gib = 1024 ** 3
    out[23] = [
        event(23, "positive", "positive", "ipfix", "flow", BASE,
              ts_end=iso(BASE + timedelta(hours=2)), src_ip="10.50.23.10",
              dst_ip="203.0.113.230", dst_port=443, service="https", app_proto="tls",
              bytes_out=5 * gib, bytes_in=200 * 1024 ** 2, duration_s=7200,
              sample_rate=1, flow_complete=True, approved=False),
        event(23, "negative", "negative", "ipfix", "flow", BASE + timedelta(seconds=1),
              ts_end=iso(BASE + timedelta(hours=2)), src_ip="10.50.23.20", src_role="backup_server",
              dst_ip="198.51.100.230", dst_port=443, service="backup", app_proto="tls",
              bytes_out=20 * gib, bytes_in=500 * 1024 ** 2, duration_s=7199,
              sample_rate=1, flow_complete=True, approved=True, policy="approved-backup"),
        event(23, "edge-sampled", "edge", "ipfix", "flow", BASE + timedelta(seconds=2),
              src_ip="10.50.23.30", dst_ip="192.0.2.230", dst_port=443,
              service="https", app_proto="tls", bytes_out=700000000, bytes_in=20000000,
              duration_s=3600, sample_rate=100, counter_layer="sampled-unscaled",
              flow_complete=True, coverage_state="sampling-uncertain", approved=False),
    ]

    out[24] = []
    for i in range(30):
        out[24].append(event(24, "positive", "positive", "ipfix", "flow",
                             BASE + timedelta(hours=i * 8), ordinal=i + 1,
                             src_ip="10.50.24.10", dst_ip="203.0.113.240", dst_port=443,
                             service="https", app_proto="tls", bytes_out=3 * 1024 ** 2,
                             bytes_in=120000, duration_s=240, approved=False,
                             coverage_state="complete", collection_interval="present"))
    for i in range(24):
        out[24].append(event(24, "negative", "negative", "ipfix", "flow",
                             BASE + timedelta(days=i * 15), ordinal=i + 1,
                             src_ip="10.50.24.20", src_role="finance_server",
                             dst_ip="198.51.100.240", dst_port=443, service="payroll_export",
                             app_proto="tls", bytes_out=4 * 1024 ** 2, bytes_in=80000,
                             duration_s=300, approved=True, policy="approved-payroll-calendar",
                             coverage_state="complete", collection_interval="present"))
    for i in range(30):
        out[24].append(event(24, "edge-gap", "edge", "ipfix", "flow",
                             BASE + timedelta(hours=i * 8), ordinal=i + 1,
                             src_ip="10.50.24.30", dst_ip="192.0.2.240", dst_port=443,
                             service="https", app_proto="tls", bytes_out=3 * 1024 ** 2,
                             bytes_in=120000, duration_s=240, approved=False,
                             coverage_state="partial", collection_interval="null-gap"))
    return out


def raw_record(row: dict[str, object], analytic_fields: list[str]) -> dict[str, object]:
    """Encode producer evidence plus an explicit, machine-auditable lineage map."""
    src = row["source"]
    common = {"fixture_id": row["fixture_id"], "case_id": row["case_id"],
              "control": row["control"], "producer": src}
    if str(src).startswith("zeek"):
        record = {"ts": row["ts"], "uid": row["correlation_key"] or row["event_id"],
                  "id.orig_h": row["src_ip"], "id.orig_p": row["src_port"],
                  "id.resp_h": row["dst_ip"], "id.resp_p": row["dst_port"],
                  "proto": row["transport"], "service": row["service"],
                  "query": row["query"], "qtype_name": row["qtype"],
                  "rcode_name": row["rcode"], "server_name": row["sni"],
                  "next_protocol": row["alpn"], "duration": row["duration_s"],
                  "orig_bytes": row["bytes_out"], "resp_bytes": row["bytes_in"],
                  "method": row["method"], "host": row["host"], "uri": row["uri"],
                  "status_code": row["status_code"], "user_agent": row["user_agent"],
                  "request_body_len": row["bytes_out"], "response_body_len": row["bytes_in"],
                  "resp_mime_types": ([row["mime_type"]] if row["mime_type"] else None),
                  "filename": row["filename"], "mime_type": row["mime_type"],
                  "file_size": row["file_size"], "file_hash": row["file_hash"],
                  "share_name": row["share_name"], "rpc_operation": row["rpc_operation"],
                  "parser_protocol": row["parser_zeek"],
                  "coverage_state": row["coverage_state"],
                  "collection_interval": row["collection_interval"]}
    elif src == "suricata":
        record = {"timestamp": row["ts"], "flow_id": row["correlation_key"] or row["event_id"],
                  "event_type": row["event_type"], "src_ip": row["src_ip"],
                  "src_port": row["src_port"], "dest_ip": row["dst_ip"],
                  "dest_port": row["dst_port"], "proto": row["transport"],
                  "app_proto": row["app_proto"], "tls": {"sni": row["sni"], "version": row["tls_version"],
                  "ja4": row["fingerprint"], "alpn": row["alpn"],
                  "client_alpns": ([row["alpn"]] if row["alpn"] else None),
                  "server_alpns": ([row["alpn"]] if row["alpn"] else None),
                  "subject": row["cert_subject"], "issuerdn": row["cert_issuer"],
                  "subjectaltname": ([str(row["cert_subject"]).removeprefix("CN=")]
                                     if row["cert_subject"] else None),
                  "validity_days": row["cert_valid_days"], "self_signed": row["cert_self_signed"],
                  "sni_cert_match": row["sni_cert_match"]},
                  "quic": {"version": row["quic_version"], "sni": row["sni"], "alpn": row["alpn"]},
                  "flow": {"bytes_toserver": row["bytes_out"], "bytes_toclient": row["bytes_in"]},
                  "smb": {"share": row["share_name"], "rpc_operation": row["rpc_operation"],
                          "filename": row["filename"], "file_size": row["file_size"]},
                  "parser_protocol": row["parser_suricata"],
                  "policy": row["policy"], "coverage_state": row["coverage_state"]}
    elif src == "ipfix":
        record = {"flowStartMilliseconds": row["ts"], "flowEndMilliseconds": row["ts_end"],
                  "sourceIPv4Address": row["src_ip"], "destinationIPv4Address": row["dst_ip"],
                  "sourceTransportPort": row["src_port"], "destinationTransportPort": row["dst_port"],
                  "protocolIdentifier": row["ip_protocol_number"], "octetDeltaCount": row["bytes_out"],
                  "reverseOctetDeltaCount": row["bytes_in"], "samplingPacketInterval": row["sample_rate"],
                  "applicationService": row["service"], "applicationProtocol": row["app_proto"],
                  "flowDurationSeconds": row["duration_s"], "flowComplete": row["flow_complete"],
                  "counterLayer": row["counter_layer"], "coverageState": row["coverage_state"],
                  "collectionInterval": row["collection_interval"]}
    elif src == "resolver":
        record = {"event_time": row["ts"], "client_ip": row["src_ip"],
                  "resolver_ip": row["dst_ip"], "transport": row["transport"],
                  "query_name": row["query"], "base_domain": row["base_domain"],
                  "qtype_name": row["qtype"], "rcode_name": row["rcode"],
                  "answer_count": row["answer_count"],
                  "first_label_length": row["dns_label_length"],
                  "first_label_entropy": row["dns_label_entropy"],
                  "sequential_label": row["sequential_label"],
                  "collection_interval": row["collection_interval"],
                  "coverage_state": row["coverage_state"]}
    elif src == "proxy":
        record = {"event_time": row["ts"], "client_ip": row["src_ip"],
                  "server_ip": row["dst_ip"], "server_port": row["dst_port"],
                  "service": row["service"], "app_protocol": row["app_proto"],
                  "channel": row["channel"], "tls_sni": row["sni"],
                  "negotiated_alpn": row["alpn"], "method": row["method"],
                  "authority": row["authority"], "uri": row["uri"],
                  "status": row["status_code"], "policy_name": row["policy"],
                  "action": row["action"], "outcome": row["outcome"],
                  "visibility_basis": row["visibility_basis"],
                  "bytes_sent": row["bytes_out"], "bytes_received": row["bytes_in"]}
    elif src == "firewall":
        record = {"event_time": row["ts"], "pre_nat_src_ip": row["src_ip"],
                  "pre_nat_src_port": row["src_port"], "destination_ip": row["dst_ip"],
                  "destination_port": row["dst_port"], "transport": row["transport"],
                  "action": row["action"], "outcome": row["outcome"],
                  "connection_state": row["connection_state"],
                  "nat_mapping_state": row["mapping_state"],
                  "policy_name": row["policy"], "ip_protocol_number": row["ip_protocol_number"],
                  "bytes_sent": row["bytes_out"], "bytes_received": row["bytes_in"],
                  "coverage_state": row["coverage_state"]}
    elif src in {"vpn_flow", "eastwest_flow", "packet"}:
        record = {"event_time": row["ts"], "src": row["src_ip"], "sport": row["src_port"],
                  "dst": row["dst_ip"], "dport": row["dst_port"], "action": row["action"],
                  "outcome": row["outcome"], "service": row["service"],
                  "bytes_sent": row["bytes_out"], "bytes_received": row["bytes_in"],
                  "session_id": row["vpn_session_id"], "assigned_ip": row["assigned_ip"],
                  "mapping_state": row["mapping_state"], "route_mode": row["route_mode"],
                  "icmp_version": row["icmp_version"], "icmp_type": row["icmp_type"],
                  "icmp_code": row["icmp_code"], "payload_len": row["payload_len"],
                  "icmp_id": row["icmp_id"], "icmp_seq": row["icmp_seq"],
                  "coverage_state": row["coverage_state"]}
    else:
        record = {"event_time": row["ts"], "src": row["src_ip"], "dst": row["dst_ip"],
                  "event_type": row["event_type"], "details": row["note"]}
    envelope: dict[str, object] = common | {
        "record": record,
        "adapter_enrichment": {},
        "enrichment_basis": (
            "Deterministic teaching-fixture role, policy, interval, or derived-field map; "
            "not claimed as native producer evidence."
        ),
        "lineage": {},
        "canonical": row,
    }
    native_paths = _native_paths(src)
    enrichment: dict[str, object] = {}
    lineage: dict[str, str] = {}
    for field in sorted(analytic_fields):
        path = native_paths.get(field)
        if path is not None:
            try:
                native_value = resolve_lineage_path(envelope, path)
            except (KeyError, TypeError):
                native_value = object()
            if native_value == row[field]:
                lineage[field] = path
                continue
        enrichment[field] = row[field]
        lineage[field] = f"adapter_enrichment:{field}"
    envelope["adapter_enrichment"] = enrichment
    envelope["lineage"] = lineage
    return envelope


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ether(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", ethertype) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    src_b = ipaddress.IPv4Address(src).packed
    dst_b = ipaddress.IPv4Address(dst).packed
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                       0x4000, 64, proto, 0, src_b, dst_b)
    head = head[:10] + struct.pack("!H", _internet_checksum(head)) + head[12:]
    return head + payload


def _udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    head = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed
    pseudo += struct.pack("!BBH", 0, 17, length)
    checksum = _internet_checksum(pseudo + head + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, checksum) + payload


def _tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
         flags: int, payload: bytes = b"") -> bytes:
    offset_flags = (5 << 12) | flags
    head = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags,
                       64240, 0, 0)
    length = len(head) + len(payload)
    pseudo = ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed
    pseudo += struct.pack("!BBH", 0, 6, length)
    checksum = _internet_checksum(pseudo + head + payload)
    return head[:16] + struct.pack("!H", checksum) + head[18:] + payload


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"


def _write_pcap_stdlib(path: Path) -> None:
    """Write the shared capture without opening sockets or reading interfaces."""
    frames: list[tuple[float, bytes]] = []
    t = BASE.timestamp()
    dns_question = _dns_name("portal.example") + struct.pack("!HH", 1, 1)
    dns_q = struct.pack("!HHHHHH", 0x501, 0x0100, 1, 0, 0, 0) + dns_question
    dns_a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.IPv4Address("192.0.2.44").packed
    dns_r = struct.pack("!HHHHHH", 0x501, 0x8580, 1, 1, 0, 0) + dns_question + dns_a
    frames.append((t, _ether(_ipv4("10.50.1.10", "203.0.113.53", 17,
                                      _udp("10.50.1.10", "203.0.113.53", 53001, 53, dns_q), 0x501))))
    frames.append((t + 0.03, _ether(_ipv4("203.0.113.53", "10.50.1.10", 17,
                                             _udp("203.0.113.53", "10.50.1.10", 53, 53001, dns_r), 0x502))))
    c, s, cp, sp = "10.50.12.10", "203.0.113.120", 50120, 8088
    req = b"GET /fixture HTTP/1.1\r\nHost: parser.test\r\nConnection: close\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"
    tcp_parts = [
        (c, s, cp, sp, 1000, 0, 0x02, b""),
        (s, c, sp, cp, 9000, 1001, 0x12, b""),
        (c, s, cp, sp, 1001, 9001, 0x10, b""),
        (c, s, cp, sp, 1001, 9001, 0x18, req),
        (s, c, sp, cp, 9001, 1001 + len(req), 0x18, resp),
        (s, c, sp, cp, 9001 + len(resp), 1001 + len(req), 0x11, b""),
    ]
    for index, args in enumerate(tcp_parts):
        src, dst, sport, dport, seq, ack, flags, payload = args
        frames.append((t + 1 + index * 0.01,
                       _ether(_ipv4(src, dst, 6, _tcp(src, dst, sport, dport, seq, ack, flags, payload),
                                    0x520 + index))))
    # A second complete, harmless session carries only SSH identification
    # banners on TCP/443.  It validates content-based identification on a port
    # whose policy normally expects TLS; it does not authenticate or execute a
    # command.
    c, s, cp, sp = "10.50.12.10", "203.0.113.122", 50122, 443
    client_banner = b"SSH-2.0-Book5Fixture_Client\r\n"
    server_banner = b"SSH-2.0-Book5Fixture_Server\r\n"
    ssh_parts = [
        (c, s, cp, sp, 2000, 0, 0x02, b""),
        (s, c, sp, cp, 12000, 2001, 0x12, b""),
        (c, s, cp, sp, 2001, 12001, 0x10, b""),
        (s, c, sp, cp, 12001, 2001, 0x18, server_banner),
        (c, s, cp, sp, 2001, 12001 + len(server_banner), 0x18, client_banner),
        (c, s, cp, sp, 2001 + len(client_banner), 12001 + len(server_banner), 0x11, b""),
    ]
    for index, args in enumerate(ssh_parts):
        src, dst, sport, dport, seq, ack, flags, payload = args
        frames.append((t + 7 + index * 0.01,
                       _ether(_ipv4(src, dst, 6, _tcp(src, dst, sport, dport, seq, ack, flags, payload),
                                    0x560 + index))))
    for index in range(3):
        body = struct.pack("!BBHHH", 8, 0, 0, 1400, index + 1) + bytes([65 + index]) * 64
        body = body[:2] + struct.pack("!H", _internet_checksum(body)) + body[4:]
        frames.append((t + 2 + index,
                       _ether(_ipv4("10.50.14.10", "203.0.113.140", 1, body, 0x540 + index))))
    inner = _ipv4("10.99.0.1", "10.99.0.2", 17,
                  _udp("10.99.0.1", "10.99.0.2", 15000, 15001, b"BOOK5-BENIGN-GRE"), 0x550)
    gre = struct.pack("!HH", 0, 0x0800) + inner
    frames.append((t + 6, _ether(_ipv4("10.50.15.10", "203.0.113.150", 47, gre, 0x551))))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for stamp, frame in frames:
            seconds = int(stamp)
            micros = int(round((stamp - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            handle.write(frame)


def generate_pcap(path: Path) -> str:
    # Always use the same writer so fixture bytes do not vary with host
    # interface-discovery permissions.  Scapy remains pinned and its package
    # and parser surfaces are version-checked by the verification harness.
    _write_pcap_stdlib(path)
    return "deterministic-stdlib-v1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    for directory in (GENERATED, RAW, PCAP, MANIFESTS, GOLDEN):
        directory.mkdir(parents=True, exist_ok=True)
    all_fixtures = fixtures_01_08() | fixtures_09_16() | fixtures_17_24()
    if sorted(all_fixtures) != list(range(1, 25)):
        raise RuntimeError("fixture set must contain exactly Hunts 01 through 24")
    expected_entities = {hunt: [f"10.50.{hunt}.10"] for hunt in range(1, 25)}
    expected_entities[2] = ["10.50.2.10", "10.50.2.11", "10.50.2.12"]
    expected_entities[7] = ["203.0.113.70"]
    expected_entities[12] = ["1:h12-positive-ssh443"]
    expected_entities[21] = ["10.250.21.10"]
    expected_entities[22] = ["10.50.22.10"]
    for hunt, rows in sorted(all_fixtures.items()):
        analytic_fields = analytic_fields_for_hunt(hunt)
        controls = {str(r["control"]) for r in rows}
        if controls != {"positive", "negative", "edge"}:
            raise RuntimeError(f"Hunt {hunt:02d} missing controls: {controls}")
        path = GENERATED / f"hunt_{hunt:02d}.jsonl"
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        raw_path = RAW / f"hunt_{hunt:02d}_raw.jsonl"
        raw_path.write_text(
            "".join(json.dumps(raw_record(row, analytic_fields), sort_keys=True) + "\n"
                    for row in rows),
            encoding="utf-8",
        )
        expected = {
            "schema_version": 1,
            "hunt": hunt,
            "listing_id": f"B05-H{hunt:02d}-SQL-01",
            "required_result_columns": [
                "hunt_id", "entity_key", "first_seen", "last_seen", "event_count",
                "score", "reason",
            ],
            "positive": [{"entity_key": key, **({} if hunt == 12 else {"decision": "DETECT"})}
                         for key in expected_entities[hunt]],
            "negative": [],
            "edge": [],
            "full": [{"entity_key": key, **({} if hunt == 12 else {"decision": "DETECT"})}
                     for key in expected_entities[hunt]],
            "score_comparison": "numeric tolerance 1e-6; exact values retained in reports/results",
        }
        (GOLDEN / f"hunt_{hunt:02d}.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
        manifest = {
            "schema_version": 1,
            "fixture_id": f"B05-H{hunt:02d}-v1",
            "created_by": "Practical Threat Hunting Book 5 deterministic fixture generator",
            "generation_mode": "offline-file-only",
            "rights_status": "Copyright © 2026 Grant Halden. All rights reserved.",
            "release_status": "Published in the official public companion repository; copyright retained and no reuse license granted.",
            "license": "All rights reserved; no redistribution license granted.",
            "sensitive_data_review": "reserved/example/private addresses only; no credentials, customer data, or malware",
            "record_count": len(rows),
            "control_counts": {name: sum(1 for r in rows if r["control"] == name)
                               for name in ("positive", "negative", "edge")},
            "time_min": min((str(r["ts"]) for r in rows), key=parse_iso),
            "time_max": max((str(r["ts_end"] or r["ts"]) for r in rows), key=parse_iso),
            "canonical_path": str(path.relative_to(ROOT)),
            "canonical_sha256": sha256(path),
            "raw_path": str(raw_path.relative_to(ROOT)),
            "raw_sha256": sha256(raw_path),
            "ground_truth": {
                "positive": "First-party suspicious-shaped behavior constructed to satisfy the bounded hunt hypothesis; not maliciousness proof.",
                "negative": "First-party benign confounder or approved operational path constructed to remain below the bounded analytic.",
                "edge": "First-party ambiguity, missing-visibility, denied-attempt, or sanctioned-lookalike case constructed to exercise evidence limits.",
                "label_basis": "Deterministic generator case construction, independently checked through control-isolated query execution."
            },
            "hunt_relationship": f"Hunt {hunt:02d}; listing B05-H{hunt:02d}-SQL-01",
            "known_artifacts": "Teaching-scale synthetic distributions and explicit policy/role enrichments are intentionally simpler than production telemetry.",
            "limitations": "Teaching-scale fixture. Thresholds are illustrative and must be re-baselined for production.",
        }
        (MANIFESTS / f"B05-H{hunt:02d}-v1.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    pcap_path = PCAP / "book5_shared_protocols_v1.pcap"
    pcap_builder = generate_pcap(pcap_path)
    if pcap_builder:
        pcap_manifest = {
            "fixture_id": "B05-PCAP-SHARED-v1", "generation_mode": "offline-file-only",
            "rights_status": "Copyright © 2026 Grant Halden. All rights reserved.",
            "release_status": "Published in the official public companion repository; copyright retained and no reuse license granted.",
            "license": "All rights reserved; no redistribution license granted.",
            "sensitive_data_review": "reserved/example/private addresses and inert bytes only",
            "path": str(pcap_path.relative_to(ROOT)), "sha256": sha256(pcap_path),
            "purpose": "Shared Zeek/Suricata/parser validation for DNS, HTTP, ICMP, and GRE evidence.",
            "packet_builder": pcap_builder,
            "scapy_import_error": SCAPY_IMPORT_ERROR,
        }
        (MANIFESTS / "B05-PCAP-SHARED-v1.json").write_text(json.dumps(pcap_manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
