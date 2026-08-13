# Hunt 14 — Cloud Logging and Defense Impairment

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate
- **Estimated time:** 45–90 minutes
- **Primary telemetry:** CloudTrail + cloud security service audit
- **ATT&CK:** T1562.008 — Disable or Modify Cloud Logs
- **Primary skill:** Control-plane tampering analysis

## Scenario Summary

Cloud attackers may attempt to reduce visibility by stopping trails, altering logging destinations, deleting flow logs, disabling alarms, modifying security services, or changing retention. Some changes are operationally legitimate, but in a well-managed environment they should be rare, automated, and attributable.

## Hunt Hypothesis

If an adversary attempts to impair cloud defenses, audit telemetry should show high-impact logging or security-control changes performed by unusual principals, from unusual context, or near other suspicious IAM and data-access activity.

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
