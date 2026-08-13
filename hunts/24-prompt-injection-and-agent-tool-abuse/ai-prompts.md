# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Review this agent execution timeline and approved tool inventory.
1. Identify tool calls or resource access outside the approved workflow.
2. Separate attempted actions from confirmed downstream actions.
3. Identify the input, retrieved content, or tool result immediately preceding each deviation.
4. List alternative explanations such as configuration changes or user-requested actions.
5. Recommend the next authoritative audit log to query.
Do not infer prompt injection solely from unusual language.
```
