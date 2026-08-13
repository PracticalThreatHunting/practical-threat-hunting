# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Build a behavioral profile for each AWS principal using source IP, user agent, region, event source, event name, and role/session context.
Rank deviations by how many independent dimensions changed at once.
For the top candidates, identify the first sensitive API sequence and list the benign operational changes that could explain it.
```
