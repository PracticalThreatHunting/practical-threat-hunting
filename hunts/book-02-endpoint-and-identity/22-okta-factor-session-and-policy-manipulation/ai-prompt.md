# AI-Assisted Analysis Prompt — Hunt 22

Use only data approved for the selected AI system. Treat the output as proposed analysis and verify every material claim against the underlying evidence.

```text
Reconstruct these Okta events using UUID, event type, actor, client, outcome, target, transaction, request, authentication context, and debug context.
Preserve raw event types and structured IDs.
Group events into candidate transactions, but identify which links are inferred rather than explicit.
Compare factor, session, policy, zone, token, and administrator actions with approved workflows.
List exact current Okta catalog entries that an analyst must verify before productionizing logic.
```
