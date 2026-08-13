# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Review these cloud audit events for possible defense impairment.
Group related changes by principal and 30-minute window.
For each cluster, identify which visibility or security control changed, whether the change was reversible, and what sensitive actions occurred immediately before and after.
Do not assume every delete/disable API is malicious; compare with known automation.
```
