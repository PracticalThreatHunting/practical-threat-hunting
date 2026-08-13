# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Analyze this OAuth/service-principal inventory and audit data.
For each new or changed application, summarize:
- publisher and owners,
- delegated vs application permissions,
- credential additions,
- first API activity,
- source IP/user agent,
- whether the app is new for the tenant.
Do not call a permission "high risk" without explaining what resource access it enables.
```
