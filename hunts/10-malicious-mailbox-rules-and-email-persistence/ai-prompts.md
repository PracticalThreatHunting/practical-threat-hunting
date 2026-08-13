# AI-Assisted Hunt Prompts

> Treat model output as a hypothesis or accelerator. Validate generated fields, queries, assumptions, joins, time ranges, and conclusions against authoritative telemetry.

## Prompt 1

```text
Parse these mailbox-rule audit events into a human-readable table with user, rule name, conditions, actions, forwarding destination, initiator/source IP, and creation time.
Flag external destinations and rules that delete, hide, or move security/financial messages.
Then correlate the creation time with the user’s authentication events without assuming the rule is malicious.
```
