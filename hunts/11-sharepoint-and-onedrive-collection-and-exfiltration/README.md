# Hunt 11 — SharePoint and OneDrive Collection and Exfiltration

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate–Advanced
- **Estimated time:** 60–120 minutes
- **Primary telemetry:** Microsoft 365 file/activity audit
- **ATT&CK:** T1213.002 — SharePoint; T1567 — Exfiltration Over Web Service (related)
- **Primary skill:** Volume and resource-access baselining

## Scenario Summary

After compromising an identity or application, an adversary may search SharePoint and OneDrive for high-value data, create sharing links, synchronize or download large volumes of files, or access sites the identity rarely uses. Normal collaboration creates large amounts of file activity, so the hunt should compare behavior with the user’s historical resource set, volume, application, and network context.

## Hunt Hypothesis

If a compromised account or application collects data from Microsoft 365, file-access telemetry should show abnormal volume, breadth, first-seen sites, mass download/synchronization, unusual sharing operations, or sensitive resource access that follows suspicious authentication or application activity.

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
