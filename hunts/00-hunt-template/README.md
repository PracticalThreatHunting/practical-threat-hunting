# Hunt XX — Hunt Title

## Hunt Snapshot

- **Difficulty:**
- **Estimated time:**
- **Primary telemetry:**
- **ATT&CK / ATLAS / other mappings:**
- **Primary skill:**
- **Last validated:**

## Threat Scenario

Describe the adversary behavior and why it matters.

## Hunt Hypothesis

**Because** an adversary may perform _X_, **we expect to observe** _Y_ evidence in _Z_ telemetry under conditions that differ from the entity's normal behavior.

## Required Telemetry and Fields

Document data sources, critical fields, retention, and known blind spots.

## Data Quality Checks

- Confirm time range and retention.
- Confirm parser / ingestion health.
- Validate timestamp semantics.
- Validate identity normalization.
- Document sampling, deduplication, and delayed ingestion.

## Establish Normal

Describe the baseline population, time period, and peer group.

## Hunting Methodology

1. Start broad enough to understand prevalence.
2. Reduce noise using context rather than arbitrary exclusions.
3. Preserve entity and time correlation keys.
4. Pivot into related telemetry.
5. Record what the evidence proves and what it cannot prove.

## Query Implementations

Store platform-specific queries under `queries/` and link them here.

## Interpretation and Investigation Pivots

Document useful pivots across user, device, application, resource, network, and time.

## Benign Explanations

List legitimate workflows that can produce the same evidence.

## Suspicious Indicators

Describe combinations of context that meaningfully raise confidence.

## AI-Assisted Hunt

Store reusable prompts in `ai-prompts.md`. Validate all AI-generated output.

## AI Validation Checklist

Prompt → Inspect → Validate → Execute → Interpret → Challenge → Pivot.

## Escalation Criteria

State what evidence justifies incident escalation and what remains a hunt finding.

## Detection Opportunities

Identify repeatable behavior worth evaluating as a production detection.

## Analyst Takeaways

Summarize the reasoning skill the hunt is designed to build.
