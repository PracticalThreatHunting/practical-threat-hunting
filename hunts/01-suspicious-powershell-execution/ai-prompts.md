# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Using the verified endpoint process schema I provide, help me hunt suspicious PowerShell.
First baseline common parent processes, users, and command-line patterns.
Then propose filters for encoded, hidden, download, and in-memory execution patterns.
Do not label a result malicious based on one keyword.
For every suspicious pattern, list the contextual evidence that would raise or lower confidence.
```
