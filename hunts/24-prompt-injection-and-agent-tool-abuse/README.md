# Hunt 24 — Prompt Injection and Agent Tool Abuse

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced
- **Estimated time:** 2–3 hours
- **Primary telemetry:** Agent inventory/observability, tool audit, endpoint/cloud logs, application traces
- **Frameworks:** MITRE ATLAS + OWASP Agentic Applications
- **Primary skill:** Detecting downstream consequences of untrusted instructions

## Scenario Summary

An enterprise AI agent can read documents, search internal systems, create tickets, and call approved tools. A user reports that after the agent summarized an external document, it unexpectedly attempted to access an internal resource and invoke a tool outside the expected workflow. The source document may have contained prompt-injection content, but the hunt focuses on the observable behavior that followed.

## Hunt Hypothesis

An AI agent received untrusted or manipulated context that caused it to invoke tools, access resources, or perform actions outside its normal task path, and the downstream actions are visible in agent, identity, application, endpoint, or cloud telemetry.

## Query Implementations

- [Illustrative current Defender/Agent 365 inventory query — revalidate fields before publication](queries/01-defender-agentsinfo-inventory.kql)
- [Provider-neutral pseudocode — table names vary by platform](queries/02-behavioral-hunt-pattern.txt)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
