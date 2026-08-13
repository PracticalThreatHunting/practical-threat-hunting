# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
For each IAM change event, summarize the initiator, target, requested permission change, source context, and whether it creates a new authentication path or expands effective privilege.
Do not infer privilege solely from the API name; explain what in requestParameters must be inspected.
Then propose a follow-on query to see whether the changed identity used the new access.
```
