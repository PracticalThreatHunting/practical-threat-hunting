# Book 5 — Network Traffic and Command-and-Control

Official companion lab for *Practical Threat Hunting: Network Traffic and Command-and-Control* by Grant Halden.

The lab contains the complete DuckDB listings for all 24 hunts, deterministic positive/negative/edge fixtures, source-shaped raw wrappers with audited lineage, golden outputs, and a safe synthetic PCAP for optional Zeek and Suricata replay.

## Quick start

Prerequisites: CPython 3.12 and [`uv`](https://docs.astral.sh/uv/). Populate the pinned environment once (this step may download packages):

```bash
uv sync --frozen
```

Then run the complete verification suite offline:

```bash
uv run --frozen --offline python -m book05_lab.verify --all --offline
```

The verifier regenerates the fixtures twice, checks byte determinism, validates every manifest and SQL listing, executes positive/negative/edge/full scopes, audits raw lineage, and writes JSON and JUnit results under `reports/`. The verification command makes no network request.

The required Python and DuckDB checks run without native sensor installations. Zeek 8.2.2, Suricata 8.0.6, cross-sensor parity, and TShark 4.6.8 are reported `NOT_RUN` when the exact optional tools are unavailable; they are never mislabeled as passes. Set `BOOK5_TOOL_ROOT` only to an authorized local tool root matching `versions.lock.json`.

## Hunt index

| Hunt | Focus | Listing |
|---:|---|---|
| 01 | Resolver Bypass and Direct-to-External DNS | [`queries/hunt_01.sql`](queries/hunt_01.sql) |
| 02 | Unauthorized Encrypted DNS Paths: DoH, DoT, and DoQ | [`queries/hunt_02.sql`](queries/hunt_02.sql) |
| 03 | High-Throughput DNS Tunneling and Exfiltration | [`queries/hunt_03.sql`](queries/hunt_03.sql) |
| 04 | Low-and-Slow DNS C2 and Algorithmic Query Behavior | [`queries/hunt_04.sql`](queries/hunt_04.sql) |
| 05 | HTTP Request/Response Shapes Consistent With C2 | [`queries/hunt_05.sql`](queries/hunt_05.sql) |
| 06 | Jitter-Aware HTTPS Beacon Timing | [`queries/hunt_06.sql`](queries/hunt_06.sql) |
| 07 | Coordinated Multi-Host Beaconing and Shared Cadence | [`queries/hunt_07.sql`](queries/hunt_07.sql) |
| 08 | TLS Handshake, Fingerprint, SNI, ALPN, and Certificate Coherence | [`queries/hunt_08.sql`](queries/hunt_08.sql) |
| 09 | QUIC, HTTP/3, and ECH Visibility Shifts | [`queries/hunt_09.sql`](queries/hunt_09.sql) |
| 10 | TLS/HTTP Authority Mismatch and Domain-Fronting-Like Patterns | [`queries/hunt_10.sql`](queries/hunt_10.sql) |
| 11 | Proxy CONNECT, Upgrade, and Long-Lived Bidirectional Relays | [`queries/hunt_11.sql`](queries/hunt_11.sql) |
| 12 | Unexpected-Port Protocols and Parser Disagreement | [`queries/hunt_12.sql`](queries/hunt_12.sql) |
| 13 | Long-Lived, Low-Throughput Command Channels | [`queries/hunt_13.sql`](queries/hunt_13.sql) |
| 14 | ICMP Tunneling and Traffic Signaling | [`queries/hunt_14.sql`](queries/hunt_14.sql) |
| 15 | GRE, IP-in-IP, and Uncommon Network-Layer Egress | [`queries/hunt_15.sql`](queries/hunt_15.sql) |
| 16 | Unauthorized Outbound SSH, Reverse-Tunnel Indicators, and Overlay Access | [`queries/hunt_16.sql`](queries/hunt_16.sql) |
| 17 | Fallback and Multi-Channel C2 Behavior | [`queries/hunt_17.sql`](queries/hunt_17.sql) |
| 18 | East-West Discovery and Service-Sweep Fan-Out | [`queries/hunt_18.sql`](queries/hunt_18.sql) |
| 19 | SMB and RPC Administrative Lateral Transfer Patterns | [`queries/hunt_19.sql`](queries/hunt_19.sql) |
| 20 | Remote-Administration Topology Deviations | [`queries/hunt_20.sql`](queries/hunt_20.sql) |
| 21 | VPN-Assigned Client Pivots and Unexpected Internal Relays | [`queries/hunt_21.sql`](queries/hunt_21.sql) |
| 22 | Suspicious Ingress Tool and File Transfer at the Network Layer | [`queries/hunt_22.sql`](queries/hunt_22.sql) |
| 23 | Bulk Egress and Upload Asymmetry | [`queries/hunt_23.sql`](queries/hunt_23.sql) |
| 24 | Low-and-Slow or Chunked Exfiltration Across Long Windows | [`queries/hunt_24.sql`](queries/hunt_24.sql) |

## Repository map

| Path | Purpose |
|---|---|
| `queries/` | Complete publication-matched SQL listings |
| `fixtures/generated/` | Canonical JSONL and producer-shaped raw wrappers |
| `fixtures/manifests/` | Counts, UTC bounds, hashes, rights, and limitations |
| `schemas/`, `adapters/` | Canonical event contract and lineage walkthrough |
| `golden/` | Expected positive/negative/edge/full result subsets |
| `book05_lab/`, `tests/` | Assertions and the one-command verifier |
| `fixtures/pcap/`, `configs/` | Safe native-sensor replay input and contract |
| `docs/` | Compatibility, known-artifact, accessibility, and SBOM notes |

## Safety and interpretation

The fixtures use private, documentation, and special-use addresses; inert DNS, HTTP, SSH-banner, ICMP, and GRE bytes; and synthetic metadata. They contain no beacon client, command executor, credential, malware sample, exploit, or live traffic generator. SQL output identifies suspicious-shaped candidates—not proof of maliciousness.

Production use requires authorization, local schema mapping, policy inventories, coverage measurement, privacy review, and re-baselined thresholds. Read [Safety and accessibility](docs/SAFETY_AND_ACCESSIBILITY.md), [Known artifacts](docs/KNOWN_ARTIFACTS.md), [Compatibility](docs/COMPATIBILITY.md), and the repository [disclaimer](../../DISCLAIMER.md).

Copyright © 2026 Grant Halden. All rights reserved. No reuse or redistribution license is granted; third-party dependencies retain their own licenses.
