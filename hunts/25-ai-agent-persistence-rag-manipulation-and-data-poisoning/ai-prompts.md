# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Compare these two agent-configuration snapshots and this knowledge-source change log.
Identify security-relevant drift in tools, connectors/MCP servers, data sources, permissions, triggers, guardrails, model, and ownership.
Then correlate each change with the modifying identity and time.
Separate confirmed configuration changes from hypotheses about their effect on model behavior.
Do not claim data poisoning unless the changed content and retrieval/runtime evidence support it.
```
