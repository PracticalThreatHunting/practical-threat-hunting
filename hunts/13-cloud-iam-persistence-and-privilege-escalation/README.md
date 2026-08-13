# Hunt 13 — Cloud IAM Persistence and Privilege Escalation

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate–Advanced
- **Estimated time:** 60–120 minutes
- **Primary telemetry:** CloudTrail IAM/STS events
- **ATT&CK:** T1098.001 — Additional Cloud Credentials; T1098.003 — Additional Cloud Roles
- **Primary skill:** Change-control and permission reasoning

## Scenario Summary

An attacker with sufficient AWS permissions can create durable access or expand privilege by adding access keys, attaching policies, modifying role trust, creating login profiles, changing group membership, or creating new policy versions. These actions are visible in CloudTrail, but large environments generate legitimate IAM change constantly. The hunt must connect the change to its initiator, target, permission impact, and subsequent use.

## Hunt Hypothesis

If an adversary establishes persistence or escalates privilege in AWS, CloudTrail will contain IAM or STS changes that are unusual for the initiating principal, expand access materially, create a new credential path, or are quickly followed by sensitive API activity using the modified identity.

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
