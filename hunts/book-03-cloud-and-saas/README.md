# Book 3 Hunts — Cloud and SaaS Environments

This directory contains the updateable implementation layer for the 24 hunts in *Practical Threat Hunting: Cloud and SaaS Environments*. The book supplies the full scenarios, reasoning, coverage gates, interpretation, validation, and detection guidance. This repository carries reference query patterns and AI-analysis prompts that can be revised when provider schemas change.

## Hunt Index

| Hunt | Focus | Platform | Difficulty | Reference pattern |
|---:|---|---|---|---|
| 01 | Unexpected Federated or Cross-Account Role-Session Chain | AWS | Advanced | [Athena SQL](queries/01-unexpected-federated-cross-account-role-session-chain.sql) |
| 02 | Centralized Authorization-Graph Drift | AWS | Advanced | [Athena SQL](queries/02-centralized-authorization-graph-drift.sql) |
| 03 | AWS Organizations Guardrail or Account-Placement Drift | AWS | Advanced | [Athena SQL](queries/03-aws-organizations-guardrail-account-placement-drift.sql) |
| 04 | Telemetry Coverage Degradation Across the Organization | AWS | Advanced | [Athena SQL](queries/04-telemetry-coverage-degradation.sql) |
| 05 | Sensitive S3 Object Access with KMS and Policy Context | AWS | Advanced | [Athena SQL](queries/05-sensitive-s3-object-access.sql) |
| 06 | Snapshot, AMI, or Database Export and Cross-Account Sharing | AWS | Advanced | [Athena SQL](queries/06-snapshot-ami-database-export-sharing.sql) |
| 07 | Cloud-Native Command Execution Through Systems Manager or EC2 Instance Connect | AWS | Advanced | [Athena SQL](queries/07-aws-cloud-native-command-execution.sql) |
| 08 | Lambda Code, Configuration, Trigger, or Invocation Abuse | AWS | Advanced | [Athena SQL](queries/08-lambda-code-configuration-trigger-invocation-abuse.sql) |
| 09 | Cloud-Native Execution Through Azure Administration Services | Azure | Advanced | [KQL](queries/09-azure-cloud-native-execution.kql) |
| 10 | Managed Identity Used Outside Its Normal Resource Graph | Azure / Entra | Advanced | [KQL](queries/10-managed-identity-resource-graph-drift.kql) |
| 11 | Azure Key Vault Reconnaissance and Sensitive-Object Access | Azure | Advanced | [KQL](queries/11-azure-key-vault-access.kql) |
| 12 | Azure Storage Access Through SAS, Shared Key, Anonymous Access, or an Unexpected Identity | Azure | Advanced | [KQL](queries/12-azure-storage-authentication-and-access.kql) |
| 13 | Managed Disk Snapshot, Clone, Attachment, or Export Staging | Azure | Advanced | [KQL](queries/13-managed-disk-export-staging.kql) |
| 14 | AKS Kubernetes API Abuse | Azure / Kubernetes | Advanced | [KQL](queries/14-aks-kubernetes-api-abuse.kql) |
| 15 | Azure Network Exposure or Egress-Path Manipulation | Azure | Advanced | [KQL](queries/15-azure-network-exposure-egress-manipulation.kql) |
| 16 | Microsoft Graph Reconnaissance or Bulk Access by an Already-Authorized Principal | Microsoft 365 / Entra | Advanced | [KQL](queries/16-microsoft-graph-reconnaissance-bulk-access.kql) |
| 17 | Unexpected Entra Device Registration or Intune Enrollment Followed by Trusted Access | Entra / Intune | Advanced | [Provider-neutral pseudocode](queries/17-entra-device-registration-intune-enrollment.txt) |
| 18 | Exchange Online Organization-Wide Mail-Flow Manipulation | Microsoft 365 | Advanced | [KQL](queries/18-exchange-online-mail-flow-manipulation.kql) |
| 19 | Microsoft Purview eDiscovery or Content Search Misuse | Microsoft Purview | Advanced | [PowerShell](queries/19-purview-ediscovery-content-search-misuse.ps1) |
| 20 | Google Workspace OAuth Client and API Activity | Google Workspace | Advanced | [Reports API pseudocode](queries/20-google-workspace-oauth-client-api-activity.txt) |
| 21 | Google Workspace Drive Sharing, Ownership, and Administrative Change | Google Workspace | Advanced | [Reports API pseudocode](queries/21-google-workspace-drive-sharing-and-admin-change.txt) |
| 22 | GitHub Actions OIDC Trust Abuse into AWS and Azure | GitHub / AWS / Azure | Advanced | [Multi-provider SQL](queries/22-github-actions-oidc-trust-abuse.sql) |
| 23 | Federated Human Identity Pivot Across Entra, AWS, and Microsoft 365 | Entra / AWS / Microsoft 365 | Advanced | [Multi-provider SQL](queries/23-federated-human-identity-pivot.sql) |
| 24 | Cross-Cloud Intrusion Reconstruction with Ephemeral Evidence | Cross-cloud | Expert | [Multi-provider SQL](queries/24-cross-cloud-intrusion-reconstruction.sql) |

## Companion Material

- [Evidence-bound AI prompts for all 24 hunts](ai-prompts.md)
- [Book 3 edition information](../../book/cloud-and-saas-environments.md)
- [Book 3 technical source notes](../../resources/book-03-source-notes.md)
- [Book 3 figure gallery](../../assets/figures/README.md#book-3--cloud-and-saas-environments)
- [Repository disclaimer](../../DISCLAIMER.md)

## Validation Status

The 24 reference patterns were statically reviewed against the primary sources listed in the source notes through August 20, 2026. Each file contains placeholders or normalized inputs that must be replaced or mapped deliberately. Static review does not establish tenant compatibility, connector availability, local field population, parser behavior, collection completeness, retention, licensing, or production readiness.

Keep raw records and their native identifiers. Treat normalized joins as derived evidence, record coverage separately from confidence, and do not convert a missing event into proof that an action did not occur.
