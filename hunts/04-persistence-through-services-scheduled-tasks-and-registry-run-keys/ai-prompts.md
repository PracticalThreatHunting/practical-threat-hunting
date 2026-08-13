# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Given a dataset of newly created services, scheduled tasks, and Run/RunOnce registry values, rank them by persistence risk.
Use creator process, creator user, target path, target prevalence, signer, and first-seen time.
Do not suppress common software automatically; explain why a candidate is likely benign and what would falsify that assumption.
```
