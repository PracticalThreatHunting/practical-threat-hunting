# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Given sign-in logs with user, source IP, result, application, user agent, and time:
1. Identify horizontal patterns that touch many accounts with few attempts per account.
2. Suggest groupings that could reveal distributed spraying across related infrastructure.
3. Do not equate failures with attack; list likely operational causes.
4. Prioritize any targeted account that later authenticated successfully from related context.
```
