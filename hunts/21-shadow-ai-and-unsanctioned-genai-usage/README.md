# Hunt 21 — Shadow AI and Unsanctioned GenAI Usage

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate
- **Estimated time:** 60–90 minutes
- **Primary telemetry:** Web/SSE/proxy, endpoint network, DNS, SaaS inventory, cloud-app activity
- **Frameworks:** MITRE ATLAS + organizational AI-use policy
- **Primary skill:** Building visibility before judging risk

## Scenario Summary

Security has approved several enterprise AI services, but analysts suspect employees are also using consumer AI sites, browser extensions, desktop clients, and direct APIs that have not been assessed. The hunt is not designed to punish experimentation or label all unapproved AI use as malicious. Its purpose is to discover where data and identities are interacting with AI services outside the organization’s known control plane so that risk can be evaluated with evidence.

## Hunt Hypothesis

Users or workloads are communicating with AI services that are not represented in the approved inventory, and some of that usage can be identified through first-seen destinations, unusual client applications, API-style traffic, or newly observed browser extensions and SaaS applications.

## Query Implementations

- [Illustrative Defender XDR query — replace discovery terms with a maintained domain/category source](queries/01-endpoint-first-seen-ai-destinations.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
