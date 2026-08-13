# Hunt 18 — Identity Compromise to Microsoft 365 Collection

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced
- **Estimated time:** 90–150 minutes
- **Primary telemetry:** Entra sign-in + Exchange/SharePoint/OneDrive/OAuth audit
- **ATT&CK:** T1078.004, T1114, T1213.002
- **Primary skill:** Following post-authentication objectives

## Scenario Summary

Identity compromise is often discovered through a sign-in alert, but the real impact depends on what happened after authentication. An attacker may read mail, search SharePoint, download OneDrive data, create forwarding rules, consent to an application, or alter security settings. The hunt should move from authentication to objectives rather than ending at “suspicious login confirmed.”

## Hunt Hypothesis

If a compromised identity is used for Microsoft 365 collection, suspicious sign-in or session context should be followed by abnormal mailbox, SharePoint, OneDrive, Graph, or OAuth activity that is rare for the account or concentrated in a short post-compromise window.

## Query Implementations

- [Sentinel KQL](queries/01-sentinel.kql)
- [Sentinel KQL](queries/02-m365-activity-pivot.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
