# Book 5 Technical Source Notes

Technical sources and volatile claims for *Practical Threat Hunting: Network Traffic and Command-and-Control* were reviewed through **September 3, 2026**. These notes preserve the principal versioned and normative references used by the first edition. Local schemas, products, and deployment behavior must still be validated before operational use.

## Versioned implementation sources

- **Zeek Project.** [Zeek 8.2.2 documentation](https://docs.zeek.org/en/v8.2.2/) is the primary source for `conn.log`, `dns.log`, `http.log`, `ssl.log`, `x509.log`, files, SSH, SMB/DCE-RPC, RDP, QUIC, tunnel, notice, weird, analyzer, health, types, optional fields, and package/configuration boundaries. [Get Zeek](https://zeek.org/get-zeek/) supplied release and support-status evidence at the cutoff.
- **Open Information Security Foundation.** [Suricata 8.0.6 User Guide](https://docs.suricata.io/en/suricata-8.0.6/) is the primary source for EVE JSON structures, flow direction and counters, application-layer metadata, TLS/QUIC/SMB/RDP support, configuration, and replay semantics. [Suricata downloads](https://suricata.io/download/) supplied stable-release evidence.
- **DuckDB Foundation.** [DuckDB release calendar](https://duckdb.org/release_calendar.html) supplied the support-window basis for choosing the LTS line. [DuckDB 1.4.5 LTS](https://github.com/duckdb/duckdb/releases/tag/v1.4.5) is the canonical engine for every publication-matched SQL listing.
- **Wireshark Foundation.** [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html), version 4.6.8 reference. TShark is optional; no validation conclusion depends on an unavailable binary.

## Flow, transport, and protocol standards

- [RFC 7011 — Specification of IPFIX](https://www.rfc-editor.org/rfc/rfc7011) defines protocol, message, template, observation-domain, transport-session, and sequence semantics.
- [RFC 7012 — IPFIX Information Model](https://www.rfc-editor.org/rfc/rfc7012) supplies the information-element typing foundation. The [IANA IPFIX Information Elements Registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml) remains the live authority for element numbers, names, types, reverse-enterprise conventions, time, counters, end reasons, and sampling.
- [RFC 9846 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc9846) is the current TLS 1.3 specification at the cutoff and obsoletes RFC 8446.
- [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849) defines ECH offer/acceptance distinctions, `ClientHelloOuter`, and protected-name boundaries.
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/info/rfc9001/), and [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114) define the transport, protection, migration, and HTTP-over-QUIC boundaries.
- [RFC 8484 — DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc8484), [RFC 7858 — DNS over TLS](https://www.rfc-editor.org/rfc/rfc7858), [RFC 8310 — Usage Profiles for DNS over TLS and DTLS](https://www.rfc-editor.org/info/rfc8310/), and [RFC 9250 — DNS over QUIC](https://www.rfc-editor.org/rfc/rfc9250) define encrypted DNS transports and their passive-observation limits.
- [RFC 1034](https://www.rfc-editor.org/info/rfc1034/), [RFC 1035](https://www.rfc-editor.org/info/rfc1035/), [RFC 7766](https://www.rfc-editor.org/info/rfc7766/), and [IANA DNS Parameters](https://www.iana.org/assignments/dns-parameters/) provide core DNS questions, resource records, caching, flags, response codes, and UDP/TCP behavior.
- [RFC 9460 — SVCB and HTTPS Resource Records](https://www.rfc-editor.org/info/rfc9460/) and [RFC 9848 — Bootstrapping ECH with DNS Service Bindings](https://www.rfc-editor.org/info/rfc9848/) provide modern service-binding and ECH-advertisement context.
- The [IANA Protocol Numbers Registry](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) is the authority for ICMP, IPv6-ICMP, IP-in-IP, GRE, ESP, and other protocol-number interpretation.
- The [Community ID specification](https://github.com/corelight/community-id-spec) informs cross-tool flow hashing, conditional on verified tuple orientation, seed, implementation, and version.

## Threat-hunting context

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/), version 19.2, supplies technique identifiers and behavioral definitions. The edition pins the [official ATT&CK v19.2 STIX release](https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2).
- Reserved examples use [RFC 2606](https://www.rfc-editor.org/info/rfc2606/), [RFC 5737](https://www.rfc-editor.org/info/rfc5737/), [RFC 3849](https://www.rfc-editor.org/info/rfc3849/), [RFC 5398](https://www.rfc-editor.org/info/rfc5398/), and the [IANA special-use domain registry](https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml).
- Evidence and AI governance were informed by [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework) and the [NIST Generative AI Profile](https://doi.org/10.6028/NIST.AI.600-1). This is not a conformance claim.

## Interpretation boundary

Standards define protocols; they do not guarantee that a sensor exposes every field. Product documentation describes supported behavior; it does not prove local configuration, placement, parsing, retention, or collection health. ATT&CK mappings organize behavioral hypotheses; they do not prove compromise or actor identity. Every production adaptation should preserve source record identifiers, UTC time, observation point, counter layer, coverage state, and the strongest defensible conclusion.
