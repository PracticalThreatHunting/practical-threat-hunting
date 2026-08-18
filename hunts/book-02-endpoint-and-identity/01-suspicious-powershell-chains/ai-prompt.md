# AI-Assisted Analysis Prompt — Hunt 01

Use only data approved for the selected AI system. Treat the output as proposed analysis and verify every material claim against the underlying evidence.

```text
Using only the verified process, script-block, network, and file fields I provide, group these PowerShell events into likely administrative families and outliers.
For each outlier, list the exact parent, account, device, command features, network destinations, and follow-on actions that differ from baseline.
Treat encoded or hidden execution as a feature, not a malicious verdict.
Identify benign explanations and the additional evidence needed to confirm or reject each explanation.
Do not decode or execute content; analyze it as inert text.
```
