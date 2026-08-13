# Hunt 12 — Compromised Cloud Credentials

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate
- **Estimated time:** 60–90 minutes
- **Primary telemetry:** AWS CloudTrail + identity/security findings
- **ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts
- **Primary skill:** Principal behavior baselining

## Scenario Summary

Stolen AWS access keys, console credentials, or temporary role credentials allow an attacker to operate through legitimate APIs. The event record may look syntactically normal because the cloud provider sees a valid credential. Hunting therefore depends on behavioral context: source network, user agent, region, service, action mix, role chaining, MFA state, and how those attributes differ from the principal’s history.

## Hunt Hypothesis

If a cloud credential is compromised, CloudTrail should show a principal making API calls from infrastructure, tooling, regions, or services that are unusual for that identity, often followed by discovery, credential access, persistence, privilege escalation, or data access.

## Query Implementations

- [Microsoft Sentinel KQL — principal behavior summary](queries/01-microsoft-sentinel-principal-behavior-summary.kql)
- [Example KQL](queries/02-first-seen-context-pivot.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
