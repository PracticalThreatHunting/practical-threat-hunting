# Hunt 09 — Malicious OAuth Consent and Service Principal Abuse

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced
- **Estimated time:** 75–120 minutes
- **Primary telemetry:** Directory audit, OAuth/app inventory, Graph/API activity
- **ATT&CK:** T1098.001 — Additional Cloud Credentials; T1528 — Steal Application Access Token
- **Primary skill:** Application identity investigation

## Scenario Summary

OAuth applications and service principals can provide durable access without the interaction patterns associated with a human sign-in. An attacker may trick a user or administrator into granting consent, add credentials to an existing application, create a new application identity, or abuse broad Microsoft Graph permissions. Once established, the application can continue operating with tokens and permissions that survive password changes.

## Hunt Hypothesis

If OAuth consent or an application identity is being abused, directory and application telemetry should show unusual consent, permission grants, service-principal creation, credential addition, or API use that is new for the tenant, broader than expected, or associated with a compromised user or administrator.

## Query Implementations

- [Microsoft Sentinel KQL — broad audit discovery](queries/01-microsoft-sentinel-broad-audit-discovery.kql)
- [Microsoft Defender XDR — Graph API pivot](queries/02-microsoft-defender-xdr-graph-api-pivot.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
