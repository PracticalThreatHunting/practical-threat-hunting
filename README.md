# Practical Threat Hunting

Official companion repository for **Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC** by **Grant Halden**.

The project focuses on durable threat-hunting methodology plus an updateable implementation layer for modern endpoint, identity, cloud, Microsoft 365, and AI-system hunts.

## What You'll Find Here

- Companion resources for 25 hands-on threat hunts
- KQL, Splunk SPL, CrowdStrike LogScale, Sigma, and provider-neutral examples where applicable
- AI-assisted hunt prompts and validation guidance
- Detection opportunities and telemetry notes
- MITRE ATT&CK / MITRE ATLAS / OWASP / NIST reference material
- Book figures, technical source notes, errata, and corrections

## Current Book

**Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC**  
*25 Hands-On Hunts Across Endpoint, Identity, Cloud, Microsoft 365, and AI Systems*  
**Grant Halden**

Status: pre-publication manuscript revision.

## Repository Structure

- [`hunts/`](hunts/) — implementation resources for the 25 hands-on hunts.
- [`resources/`](resources/) — AI-validation, framework, query, source, and hunt-library references.
- [`book/`](book/) — edition information, errata, and companion references.
- [`assets/`](assets/) — figures and supporting repository assets.

## Book vs. Repository

The **book is the durable teaching layer**: methodology, reasoning, interpretation, investigation pivots, and analyst judgment.

The **repository is the updateable implementation layer**: query syntax, field names, current schemas, source links, corrections, and platform-specific variants.

Queries and examples must be reviewed and adapted to your organization's telemetry, schemas, authorization boundaries, and security controls before use. See [DISCLAIMER.md](DISCLAIMER.md).

## Corrections and Feedback

If you identify an outdated field, broken query, book correction, or technical issue, open the appropriate GitHub Issue. External pull requests are not currently accepted.
