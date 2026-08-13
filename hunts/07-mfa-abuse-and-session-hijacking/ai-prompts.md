# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Create a timeline for this user that separates:
- interactive authentication,
- MFA events,
- non-interactive/token activity,
- Microsoft 365 resource access,
- security-setting changes.
Do not infer session theft from geography alone. Identify which events cannot be explained by the same device/network/session context and list the evidence needed to confirm compromise.
```
