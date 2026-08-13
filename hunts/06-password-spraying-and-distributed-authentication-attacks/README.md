# Hunt 06 — Password Spraying and Distributed Authentication Attacks

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Foundational–Intermediate
- **Estimated time:** 45–75 minutes
- **Primary telemetry:** Entra/IdP sign-in logs
- **ATT&CK:** T1110.003 — Password Spraying
- **Primary skill:** Horizontal authentication analysis

## Scenario Summary

Password spraying avoids the noisy pattern of many passwords against one account. Instead, an attacker tests one or a few likely passwords across many accounts, often distributing attempts across IP addresses to weaken simple thresholds. The hunt must therefore analyze the relationship among source infrastructure, user breadth, failure reasons, and eventual success.

## Hunt Hypothesis

If an adversary conducts password spraying, sign-in telemetry should show one or more sources attempting authentication across an unusually broad set of users within a limited period, possibly followed by successful authentication for one of the targeted accounts.

## Query Implementations

- [Microsoft Sentinel KQL](queries/01-microsoft-sentinel.kql)
- [Microsoft Defender XDR alternative — current Entra sign-in schema](queries/02-microsoft-defender-xdr-entra-sign-in-schema.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
