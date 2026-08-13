# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
For each process/destination pair, calculate or summarize:
- number of connections,
- unique devices,
- first/last seen,
- median and variance of inter-arrival time if available,
- destination prevalence,
- process prevalence.
Rank candidates only after considering known update, telemetry, security, and synchronization software.
```
