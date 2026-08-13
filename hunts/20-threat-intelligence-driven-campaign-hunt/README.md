# Hunt 20 — Threat-Intelligence-Driven Campaign Hunt

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced capstone
- **Estimated time:** 2–4 hours
- **Primary telemetry:** Multiple domains based on report
- **ATT&CK:** Varies by campaign
- **Primary skill:** Turning external reporting into local hypotheses

## Scenario Summary

Assume a new threat report describes an intrusion set targeting organizations in your industry. The report says the actor uses phishing for initial access, PowerShell for execution, cloud identity for persistence, and cloud storage for collection. It includes several hashes and domains, but the infrastructure is likely to change. The goal is to turn the report into a local hunt rather than merely loading IOCs into a blocklist.

## Query Implementations

- [Illustrative KQL — campaign seed across process and network telemetry](queries/01-campaign-seed-across-process-and-network-telemetry.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
