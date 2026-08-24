# Book 4 Hunts — Threat Intelligence and Adversary Infrastructure

This directory contains the updateable implementation layer for the 24 hunts in *Practical Threat Hunting: Threat Intelligence and Adversary Infrastructure*. The book supplies the evidence model, scenarios, source and accuracy gates, interpretation guidance, validation requirements, and operational decision criteria. This repository carries the reference patterns and evidence-bound AI prompts that can be revised when standards, provider schemas, or collection methods change.

## Hunt Index

| Hunt | Focus | Evidence surface | Difficulty | Reference pattern |
|---:|---|---|---|---|
| 01 | Lookalike and Newly Registered Domains Targeting the Organization | Domain normalization, RDAP, DNS, CT, internal DNS | Advanced | [Python](queries/01-lookalike-newly-registered-domains.py) |
| 02 | Registration Cohorts and Registrar Reuse | RDAP snapshots and registration cohorts | Advanced | [Normalized SQL](queries/02-registration-cohorts-registrar-reuse.sql) |
| 03 | Nameserver, SOA, and Mail Infrastructure Reuse | NS, SOA, MX, and effective-dated DNS | Advanced | [Normalized SQL](queries/03-nameserver-soa-mail-reuse.sql) |
| 04 | Passive DNS Resolution Chains and Shared Hosting | Passive DNS and enterprise retrohunt evidence | Advanced | [Normalized SQL](queries/04-passive-dns-shared-hosting.sql) |
| 05 | Fast-Flux, Rapid Rotation, and TTL Behavior | DNS observations, answer rotation, TTLs, and networks | Advanced | [Python](queries/05-fast-flux-rotation-ttl.py) |
| 06 | Certificate Transparency and TLS Identity Pivots | CT entries, certificates, TLS deployments, and DNS | Advanced | [Normalized SQL](queries/06-certificate-transparency-tls-pivots.sql) |
| 07 | ASN, VPS, CDN, and Hosting-Network Change | BGP prefixes, origin ASNs, providers, and network state | Advanced | [Normalized SQL](queries/07-asn-vps-cdn-hosting-change.sql) |
| 08 | Dormant, Parked, Resurrected, and Repurposed Infrastructure | Registration, DNS, CT, content, and lifecycle episodes | Advanced | [Normalized SQL](queries/08-dormant-parked-repurposed-infrastructure.sql) |
| 09 | Sender-Domain and Authentication-Path Mismatch | Email identities, SPF, DKIM, DMARC, and sender inventory | Advanced | [Microsoft Defender XDR KQL](queries/09-sender-domain-authentication-mismatch.kql) |
| 10 | Executive, Brand, and Vendor Impersonation | Message identity, display-name, domain, and authorization context | Advanced | [Microsoft Defender XDR KQL](queries/10-executive-brand-vendor-impersonation.kql) |
| 11 | Credential-Phishing Page and Kit Clustering | Captured page structure, resources, paths, and form behavior | Advanced | [Offline Python](queries/11-credential-phishing-kit-clustering.py) |
| 12 | URL Shorteners, QR Codes, and Redirect Chains | Message URLs, QR artifacts, redirects, and click evidence | Advanced | [Microsoft Defender XDR KQL](queries/12-shorteners-qr-redirect-chains.kql) |
| 13 | Payload-Hosting and Download-Path Reuse | URLs, paths, HTTP metadata, payloads, and internal contacts | Advanced | [Normalized SQL](queries/13-payload-hosting-download-reuse.sql) |
| 14 | Malware Sample-to-Infrastructure Expansion | Approved sample reports and typed artifact relationships | Expert | [Offline Python](queries/14-malware-sample-infrastructure-expansion.py) |
| 15 | C2 Destination Clusters in Enterprise Telemetry | DNS, endpoint network, proxy, firewall, and asset context | Expert | [Microsoft Defender XDR KQL](queries/15-c2-destination-clusters.kql) |
| 16 | Legitimate Cloud, CDN, and Web-Service Abuse | Multi-tenant service, account, object, URL, and contact evidence | Expert | [Normalized SQL](queries/16-legitimate-service-abuse.sql) |
| 17 | DGA and Algorithmic Domain Bursts | DNS cohorts, lexical features, NXDOMAINs, processes, and contacts | Advanced | [Python](queries/17-dga-algorithmic-domain-bursts.py) |
| 18 | Infrastructure Churn and Replacement Discovery | Effective-dated graph edges and replacement sequences | Advanced | [SQL-like pseudocode](queries/18-infrastructure-churn-replacement.sql) |
| 19 | Temporal Cohorts and Campaign Windows | Multi-source events, intervals, and campaign candidates | Advanced | [Normalized SQL](queries/19-temporal-cohorts-campaign-windows.sql) |
| 20 | Cross-Campaign Infrastructure Reuse | Frozen campaign graphs, shared traits, and source dependencies | Advanced | [Normalized SQL](queries/20-cross-campaign-infrastructure-reuse.sql) |
| 21 | New Infrastructure Emerging from Known Clusters | Constrained graph-frontier expansion | Advanced | [Recursive SQL](queries/21-new-infrastructure-known-clusters.sql) |
| 22 | ATT&CK Procedure-to-Infrastructure Hypotheses | ATT&CK STIX objects, procedures, and collection hypotheses | Advanced | [Python STIX](queries/22-attack-procedure-infrastructure-hypotheses.py) |
| 23 | Actor Alias and Intrusion-Set Resolution | Namespaced actor claims and typed overlap relationships | Expert | [Normalized SQL](queries/23-actor-alias-intrusion-set-resolution.sql) |
| 24 | Competing Hypotheses and Attribution Confidence | Claim evidence, contradictions, alternatives, and dependence | Expert | [Python](queries/24-competing-hypotheses-attribution.py) |

## Companion Material

- [Evidence-bound AI prompts for all 24 hunts](ai-prompts.md)
- [Book 4 edition information](../../book/threat-intelligence-and-adversary-infrastructure.md)
- [Book 4 technical source notes](../../resources/book-04-source-notes.md)
- [Book 4 release manifest](../../resources/book-04-release-manifest.yml)
- [Book 4 figure gallery](../../assets/figures/README.md#book-4--threat-intelligence-and-adversary-infrastructure)
- [Repository disclaimer](../../DISCLAIMER.md)

## Validation Status

The 24 reference patterns were extracted from the publication manuscript and reviewed against the primary sources listed in the Book 4 source notes through August 24, 2026. Python patterns receive parser validation in repository preflight. SQL and KQL files receive static syntax, interval, cutoff, null-handling, and schema-contract review under their stated normalized or provider-specific assumptions.

Static review does not establish production compatibility, provider coverage, source independence, parser behavior, local field population, retention, licensing, safe thresholds, or attribution accuracy. Preserve raw values, source record identifiers, collection times, relationship validity intervals, and coverage state. Never treat a shared provider, ASN, certificate, registrar, nameserver, malware-family name, actor label, or ATT&CK mapping as proof of common control by itself.

All domains, addresses, email identities, hashes, organizations, campaigns, and activity clusters in these examples are reserved documentation values or synthetic fixtures unless a source note explicitly states otherwise. The reference patterns must not perform live scanning, browsing, authentication, detonation, blocking, or submission to public analysis services.
