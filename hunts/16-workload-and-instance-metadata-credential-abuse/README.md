# Hunt 16 — Workload and Instance Metadata Credential Abuse

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced
- **Estimated time:** 75–120 minutes
- **Primary telemetry:** CloudTrail + workload/network/endpoint telemetry
- **ATT&CK:** T1552.005 — Cloud Instance Metadata API
- **Primary skill:** Tracking temporary workload credentials

## Scenario Summary

Cloud workloads often receive temporary credentials through instance profiles, workload identities, or metadata services. If an attacker compromises the workload, those credentials can be stolen and used to call cloud APIs. CloudTrail records the API use, but not necessarily the local act of retrieving credentials from the metadata service. The hunt must connect workload behavior with the downstream identity session.

## Hunt Hypothesis

If workload credentials are stolen or misused, the role or workload identity should appear in CloudTrail from source context, user agents, regions, services, or API families that are inconsistent with the workload that normally owns the credentials. Host or network telemetry may also show suspicious metadata-service access preceding the anomaly.

## Query Implementations

- [Microsoft Sentinel KQL — role context](queries/01-microsoft-sentinel-role-context.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
