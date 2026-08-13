# Hunt 15 — Cloud Data Collection and Exfiltration

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced
- **Estimated time:** 75–150 minutes
- **Primary telemetry:** CloudTrail management + data events, object/storage audit
- **ATT&CK:** T1530 — Data from Cloud Storage
- **Primary skill:** Separating control-plane preparation from data-plane access

## Scenario Summary

Cloud data theft can involve direct object reads, snapshots, database exports, replication, sharing-policy changes, or staging resources for later transfer. Management events show preparation and permission changes; data events may be required to see individual object access. A hunt that only ingests management events can therefore detect the setup for exfiltration without observing the actual reads.

## Hunt Hypothesis

If an adversary collects or stages cloud data, audit telemetry should show unusual access to storage or database resources, creation or sharing of snapshots/exports, policy changes that expand external access, or an abnormal increase in data-plane activity by a principal whose behavior recently changed.

## Query Implementations

- [Microsoft Sentinel KQL](queries/01-microsoft-sentinel.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
