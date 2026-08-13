# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Review these directory role-management events.
Extract: initiator, target identity, role, operation, result, timestamp, and any justification or PIM context present.
Rank events by privilege impact and deviation from the initiator’s historical behavior.
Then propose the first three actions to pivot on for each high-risk target identity.
```
