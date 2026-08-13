# Hunt 08 — Suspicious Privileged Role Activity

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate
- **Estimated time:** 45–90 minutes
- **Primary telemetry:** Directory audit + privileged identity management logs
- **ATT&CK:** T1098.003 — Additional Cloud Roles
- **Primary skill:** Privilege-change context

## Scenario Summary

Cloud privilege can change in seconds. An adversary with access to a sufficiently privileged identity may add a role assignment, activate eligible privilege, alter a group that grants access, or manipulate an application/service principal. The event may be legitimate and still high risk. Hunting focuses on who initiated the change, what privilege was granted, to whom, from what context, and what happened immediately afterward.

## Hunt Hypothesis

If an adversary escalates or persists through cloud privilege changes, directory audit logs should record unusual role assignments, activations, membership changes, or privilege-related application changes that differ from normal administrative workflows or occur near other suspicious identity activity.

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
