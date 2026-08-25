# Book 4 — Threat Intelligence and Adversary Infrastructure

**Practical Threat Hunting: Threat Intelligence and Adversary Infrastructure**<br>
*24 Hands-On Hunts for the AI-Augmented SOC*<br>
**Grant Halden**

Status: **Publication setup in progress — First Edition, August 2026**

- Paperback ISBN: `9798194699377`
- Kindle ASIN: pending KDP assignment
- Paperback ASIN: pending KDP assignment

## Scope

Book 4 converts external intelligence, infrastructure observations, and actor claims into reproducible internal hunts. Its 24 hunts cover domains, registration cohorts, DNS, certificates, hosting networks, phishing and impersonation, redirect and payload-delivery chains, malware and command-and-control infrastructure, legitimate-service abuse, infrastructure churn, campaign windows, actor-alias resolution, and competing attribution hypotheses.

The book treats threat intelligence as time-bounded evidence rather than a feed or reputation score. It preserves source lineage, relationship meaning, collection time, validity intervals, source dependence, coverage, contradictory evidence, and alternative explanations. ATT&CK is used to organize behavioral and collection questions, not as proof of maliciousness, actor identity, or campaign membership.

The running scenario uses Greyhaven Robotics and `CLUSTER-LANTERN-27`, both fictional. All example domains, IP addresses, email identities, hashes, infrastructure, and results are reserved documentation values or synthetic fixtures unless a source note explicitly states otherwise.

## Companion Resources

- [All 24 Book 4 hunts and reference patterns](../hunts/book-04-threat-intelligence-and-infrastructure/README.md)
- [Book 4 evidence-bound AI prompts](../hunts/book-04-threat-intelligence-and-infrastructure/ai-prompts.md)
- [Book 4 figure gallery](../assets/figures/README.md#book-4--threat-intelligence-and-adversary-infrastructure)
- [Book 4 technical source notes](../resources/book-04-source-notes.md)
- [Book 4 release manifest](../resources/book-04-release-manifest.yml)
- [Series errata](errata.md)
- [Repository disclaimer](../DISCLAIMER.md)

## Technical Provenance

Primary technical claims, standards references, provider documentation, ATT&CK mappings, and source links were reviewed through **August 24, 2026**. Enterprise ATT&CK 19.2, released August 6, 2026, is the edition-pinned ATT&CK release.

The 24 reference patterns received static review under their stated schemas and assumptions. Python patterns are parsed during repository preflight. SQL and KQL patterns require deliberate mapping to deployed schemas and execution against approved fixtures before operational use. Static review does not establish production compatibility, telemetry completeness, source independence, local field population, parser behavior, retention, licensing, safe thresholds, or a valid attribution judgment.

The publication manuscript and KDP upload files are not stored in this public repository.
