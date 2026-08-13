# Hunt 10 — Malicious Mailbox Rules and Email Persistence

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate
- **Estimated time:** 45–75 minutes
- **Primary telemetry:** Exchange/Microsoft 365 audit
- **ATT&CK:** T1114.003 — Email Forwarding Rule
- **Primary skill:** Persistence through collaboration controls

## Scenario Summary

A compromised mailbox can be made useful even after the attacker loses the original interactive session. Forwarding rules, inbox rules, transport settings, or other mailbox changes can silently redirect messages, hide replies, move security notifications, or maintain visibility into conversations. The same features are heavily used for legitimate email organization, so destination and rule behavior matter.

## Hunt Hypothesis

If an attacker creates email persistence, Microsoft 365 audit logs should show new or modified inbox/forwarding rules, mailbox forwarding settings, or related changes that direct messages externally, suppress security-relevant content, or differ from the user’s historical behavior.

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
