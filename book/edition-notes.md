# Series Edition Notes

## Book 1 — Modern Techniques for the AI-Augmented SOC

Status: **Published — First Edition, August 2026**

- Technical verification date for the publication revision: **13 August 2026**.
- Paperback ISBN: `9798192696538`.
- Kindle ASIN: `B0HFGYN38J`.
- Paperback ASIN: `B0HFHD55GB`.
- The edition uses MITRE ATT&CK v19 terminology, AI-augmented hunting methodology, Microsoft Defender XDR and Microsoft Entra schema references, and AWS AI-workload observability guidance.

## Book 2 — Endpoint and Identity Threats

Status: **Scheduled for publication September 3, 2026 — Kindle pre-order live**

- Technical verification and external-link review date: **17 August 2026**.
- Scheduled publication date: **3 September 2026**.
- Kindle ASIN: `B0HFLS6MVC`.
- Paperback ASIN: `B0HFNDYLTJ`.
- Paperback ISBN: `9798193349570`.
- The edition contains 24 hunts spanning Windows endpoint behavior, PowerShell, credential access, persistence, lateral movement, Microsoft Entra ID, Okta, Kerberos, directory control, and cross-domain investigation.
- Its 34 KQL and SPL examples received static syntax-and-schema review against the primary sources listed in [Book 2 technical source notes](../resources/book-02-source-notes.md).
- Static review does not establish tenant compatibility, connector availability, local field population, retention, licensing, or production readiness.

## Book 3 — Cloud and SaaS Environments

Status: **Published — First Edition, August 2026**

- Technical verification and external-link review date: **August 20, 2026**.
- Paperback ISBN: `9798193986522`.
- Kindle ASIN: `B0HFZHHHGR`.
- Paperback ASIN: `B0HFZGYX3X`.
- Amazon A+ content `Practical Threat Hunting - Book 3 A+ Content` was approved and published August 21, 2026 and applied to two Book 3 ASINs.
- The edition contains 24 hunts spanning AWS, Azure, Microsoft Entra ID, Microsoft 365, Google Workspace, GitHub Actions OIDC, federated identity, and cross-cloud reconstruction.
- Its 24 reference patterns received static syntax-and-schema review under the assumptions documented in the manuscript and companion files.
- Static review does not establish tenant compatibility, connector availability, local field population, identity-map completeness, collection coverage, retention, licensing, or production readiness.

## Book 4 — Threat Intelligence and Adversary Infrastructure

Status: **Publication setup in progress — First Edition, August 2026**

- Technical verification and external-link review date: **August 24, 2026**.
- Paperback ISBN: `9798194699377`.
- Kindle and paperback ASINs are pending KDP assignment.
- The edition contains 24 hunts spanning domains, registration, DNS, certificates, hosting networks, phishing and impersonation, redirect and payload chains, malware and command-and-control infrastructure, legitimate-service abuse, campaign tracking, actor-context resolution, and competing attribution hypotheses.
- Enterprise ATT&CK 19.2, released August 6, 2026, is the edition-pinned ATT&CK reference.
- Its 24 reference patterns received static review under the assumptions documented in the manuscript, companion files, and [Book 4 release manifest](../resources/book-04-release-manifest.yml).
- Python patterns receive parser validation during repository preflight. SQL and KQL patterns remain reference implementations until mapped to a deployed schema and executed against approved fixtures.
- Static review does not establish provider coverage, source independence, local field population, collection completeness, parser behavior, retention, licensing, production readiness, or attribution accuracy.

Repository resources can be revised independently of the printed editions when schemas, links, or implementation details change.
