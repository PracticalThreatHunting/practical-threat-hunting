# Hunt 17 — Endpoint Compromise to Cloud Access

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced
- **Estimated time:** 90–150 minutes
- **Primary telemetry:** Endpoint + browser/session + identity + cloud audit
- **ATT&CK:** T1078.004 and related execution/session techniques
- **Primary skill:** Entity and time correlation across domains

## Scenario Summary

A compromised endpoint can become a bridge into cloud services. The attacker may steal browser sessions, retrieve cached credentials, access cloud consoles from the victim device, or use command-line tools with credentials available on the system. Endpoint and cloud teams can each see only half the story unless the hunt correlates device activity with authentication and cloud API use.

## Hunt Hypothesis

If an endpoint compromise leads to cloud access, suspicious process or browser activity on the device should align in time with new or unusual cloud authentication, session context, or API activity for the same user or workload identity.

## Query Implementations

- [Defender XDR KQL](queries/01-defender-xdr.kql)
- [Sentinel KQL — AWS example](queries/02-cloud-side-pivot.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
