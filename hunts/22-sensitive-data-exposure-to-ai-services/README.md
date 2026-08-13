# Hunt 22 — Sensitive Data Exposure to AI Services

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced
- **Estimated time:** 90–150 minutes
- **Primary telemetry:** DLP/Purview, proxy/SSE, endpoint file activity, browser/app telemetry, AI audit logs
- **Frameworks:** NIST AI RMF + OWASP GenAI risk concepts
- **Primary skill:** Correlating data sensitivity with AI destinations

## Scenario Summary

An organization allows several AI tools for general productivity but prohibits uploading source code, regulated records, customer secrets, export-controlled information, and certain internal documents. A DLP alert suggests that a sensitive file may have been submitted to an AI service. The hunt must determine whether this is an isolated policy event, a broader pattern, or evidence of account compromise or automated exfiltration.

## Hunt Hypothesis

Sensitive files or text are being transferred to AI services through browser uploads, copy/paste, API requests, extensions, or integrated applications, and the behavior can be correlated across data-classification events, endpoint activity, web transactions, and AI-provider audit telemetry.

## Query Implementations

- [Illustrative correlation pattern — use real DLP/sensitivity telemetry where available](queries/01-sensitive-file-to-ai-destination-correlation.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
