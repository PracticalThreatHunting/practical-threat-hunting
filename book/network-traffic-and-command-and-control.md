# Book 5 — Network Traffic and Command-and-Control

**Practical Threat Hunting: Network Traffic and Command-and-Control**<br>
*24 Hands-On Hunts for Network Behavior, Covert Channels, Lateral Movement, and Exfiltration*<br>
**Grant Halden**

Status: **Companion resources available — First Edition, September 2026**

Amazon identifiers are pending publication assignment.

## Scope

Book 5 focuses on behavior moving through enterprise networks. It treats network telemetry as evidence observed at a specific aperture—not as a universal record of endpoint intent. Its 24 hunts cover resolver bypass, encrypted DNS, DNS tunneling, HTTP and HTTPS beaconing, TLS and certificate coherence, QUIC and ECH visibility changes, proxy relays, protocol mismatch, low-throughput command channels, ICMP and GRE tunneling, SSH forwarding, channel switching, east-west fan-out, SMB/RPC paths, remote administration, VPN attribution, suspicious ingress, and bulk or low-and-slow exfiltration.

The edition keeps tuple orientation, observation point, counter layer, time, collection health, NAT/VPN identity, policy context, and parser disagreement attached to every conclusion. A suspicious traffic shape is a hunt candidate; it does not by itself prove compromise, command execution, data theft, or attribution.

## Companion resources

- [Deterministic lab and all 24 publication-matched SQL listings](../hunts/book-05-network-traffic-and-command-control/README.md)
- [Book 5 figure gallery](../assets/figures/README.md#book-5--network-traffic-and-command-and-control)
- [Book 5 technical source notes](../resources/book-05-source-notes.md)
- [Book 5 release manifest](../resources/book-05-release-manifest.yml)
- [Series errata](errata.md)
- [Repository disclaimer](../DISCLAIMER.md)

## Technical provenance

Primary standards, project documentation, software versions, ATT&CK mappings, and volatile technical claims were reviewed through **September 3, 2026**. Enterprise ATT&CK 19.2 is the edition-pinned ATT&CK release.

All 24 SQL listings are executable under DuckDB 1.4.5 against deterministic, synthetic fixtures. The offline verifier checks fixture regeneration, manifest and lineage hashes, canonical schemas, positive/negative/edge controls, and golden outputs. Optional native replay is version-bound to Zeek 8.2.2 and Suricata 8.0.6; TShark 4.6.8 remains optional and must be reported `NOT_RUN` when unavailable.

The publication manuscript and KDP upload files are not stored in this public repository.
