# Hunt 18 — Privileged Role and Group Escalation

Book 2 companion implementation for Chapter 23 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 75-150 minutes
- **Primary telemetry:** Directory audit, privileged identity management, group and role inventory
- **ATT&CK:** T1098 - Account Manipulation; T1078.004 - Cloud Accounts
- **Primary skill:** Connecting actor, target, privilege, and resulting use

## Hunt Hypothesis

If privilege is being escalated improperly and the relevant changes are audited, telemetry may show a rare or unauthorized actor changing a high-impact role or group, an unusual activation pattern, or a new privilege followed quickly by sensitive administrative activity.

## Required Telemetry

- Audit operation, timestamp, result, actor, target, and correlation ID.
- Stable IDs and display names for users, groups, roles, service principals, and applications.
- Modified properties with old and new values.
- Eligible and active role assignments, activation reason, approval, and duration.
- Privileged group inventory and business owner.
- Sign-in and administrative activity before and after the change.

## Reference Queries

- [Microsoft Sentinel KQL - Privilege Change Candidates](queries/01-microsoft-sentinel-kql-privilege-change-candidates.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

High-value sequences include privileged role grant followed by mailbox, application, policy, or identity changes; assignment by a rare application actor; self-assignment; permanent privilege outside the expected path; and rapid grant-use-remove behavior. Detection should preserve modified properties and correlation identifiers.

## Analyst Takeaway

Privilege analysis is complete only when you know who granted what to whom and what happened next.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
