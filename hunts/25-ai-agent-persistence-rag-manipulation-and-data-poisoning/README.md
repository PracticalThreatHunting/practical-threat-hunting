# Hunt 25 — AI Agent Persistence, RAG Manipulation, and Data Poisoning

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced capstone
- **Estimated time:** 2–4 hours
- **Primary telemetry:** Agent configuration, data-source audit, RAG/vector pipeline, IAM, application/cloud logs
- **Frameworks:** MITRE ATLAS + OWASP Agentic Applications
- **Primary skill:** Detecting manipulation of agent context and long-lived configuration

## Scenario Summary

An internal AI agent begins producing unusual recommendations after a knowledge-base update. No obvious account takeover is visible. Investigation shows that the agent relies on several data sources, retrieval indexes, tools, memory/context stores, and scheduled ingestion jobs. The hunt must determine whether the behavior reflects normal content change, poisoned retrieval data, modified agent configuration, malicious tool metadata, or unauthorized persistence.

## Hunt Hypothesis

An attacker or unauthorized user has changed an agent’s configuration, tools, connected data sources, memory/context, retrieval corpus, ingestion pipeline, or tool metadata in a way that persists across sessions and influences future agent behavior.

## Query Implementations

- [Current Microsoft-style inventory concept — persist snapshots externally to compare changes over time](queries/01-defender-agentsinfo-snapshot.kql)
- [Provider-neutral pattern](queries/02-configuration-diff-pseudocode.txt)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
