# Book 3 — Cloud and SaaS Environments

**Practical Threat Hunting: Cloud and SaaS Environments**<br>
*24 Hands-On Hunts Across AWS, Azure, Microsoft 365, Google Workspace, and GitHub*<br>
**Grant Halden**

Status: **First edition complete — Amazon identifiers pending**

- Paperback ISBN: `9798193986522`
- Kindle ASIN: pending
- Paperback ASIN: pending

## Scope

Book 3 treats cloud and SaaS investigations as evidence-correlation problems spanning identity, authorization, control-plane, data-plane, workload, application, and network records. Its 24 hunts cover AWS, Azure, Microsoft Entra ID, Microsoft 365, Google Workspace, GitHub Actions OIDC, federated identity pivots, and cross-cloud reconstruction.

The book emphasizes what each record can prove, what it cannot prove, how collection gaps constrain conclusions, and how to preserve raw evidence while using AI to assist with normalization, timelines, graph construction, and contradiction checks.

## Companion Resources

- [All 24 Book 3 hunts and reference query patterns](../hunts/book-03-cloud-and-saas/README.md)
- [Book 3 evidence-bound AI prompts](../hunts/book-03-cloud-and-saas/ai-prompts.md)
- [Book 3 figure gallery](../assets/figures/README.md#book-3--cloud-and-saas-environments)
- [Book 3 Amazon A+ content package](../assets/a-plus/book-03-cloud-saas/README.md)
- [Book 3 technical source notes](../resources/book-03-source-notes.md)
- [Series errata](errata.md)
- [Repository disclaimer](../DISCLAIMER.md)

## Technical Provenance

Technical definitions, provider behavior, schemas, field names, query operators, and limitations were checked against the primary documentation listed in the source notes through **August 20, 2026**.

The 24 reference query patterns received static syntax-and-schema review under their stated assumptions. They were not executed in every tenant, account, subscription, organization, workspace, licensing tier, connector, parser, or retention configuration. Before operational use, confirm the live schema, field population, collection scope, identity mapping, clock behavior, authorization boundary, local thresholds, and required exclusions.

The manuscript and publication upload files are not stored in this public repository.
