# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
I have process telemetry for these dual-use Windows binaries: rundll32, regsvr32, mshta, certutil, bitsadmin, wmic, cscript, and wscript.
Help me profile normal parent processes, target paths, command-line forms, and network behavior before applying suspicious filters.
Return a two-column explanation: "why this pattern can be benign" and "what additional evidence would make it suspicious."
```
