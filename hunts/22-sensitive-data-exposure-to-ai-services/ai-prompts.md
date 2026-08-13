# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
I have DLP, endpoint, identity, and web events for a suspected AI data-exposure case.
Build a timeline that separates:
- confirmed facts,
- plausible correlations,
- missing evidence,
- benign explanations,
- indicators of account compromise.
Do not infer that a file was uploaded solely because file access and an AI connection occurred close together.
```
