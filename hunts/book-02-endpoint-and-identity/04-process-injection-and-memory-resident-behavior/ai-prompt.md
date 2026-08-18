# AI-Assisted Analysis Prompt — Hunt 04

Use only data approved for the selected AI system. Treat the output as proposed analysis and verify every material claim against the underlying evidence.

```text
Using the verified source-process, target-process, process-access, module, network, and child-process events I provide, rank unusual source-target relationships.
For each result, identify what is directly observed, which injection technique is only a hypothesis, and which additional sensor or memory evidence would be required.
Compare the source-target pair with fleet prevalence and known software behavior.
Do not infer an API call or memory operation that is not present in the telemetry.
```
