# Hunt 17 — Dormant, Break-Glass, and Rarely Used Account Abuse

Book 2 companion implementation for Chapter 22 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate
- **Estimated time:** 60-120 minutes
- **Primary telemetry:** Sign-ins, account inventory, privileged-access records, audit logs
- **ATT&CK:** T1078 - Valid Accounts
- **Primary skill:** Applying account purpose and inactivity context

## Hunt Hypothesis

If a dormant or exceptional account is abused, available records may show authentication or administrative activity after a long inactivity period, from a new context, or outside the account's documented use process.

## Required Telemetry

- Stable account ID, account type, owner, purpose, status, and privilege.
- Created, enabled, disabled, credential-change, and last-use timestamps.
- Interactive and non-interactive sign-ins.
- Approved emergency-use records and change tickets.
- Source, device, client, application, authentication method, and post-login actions.
- Group, role, application, and resource assignments.

## Reference Queries

- [Microsoft Sentinel KQL - Recent Use After Inactivity](queries/01-microsoft-sentinel-kql-recent-use-after-inactivity.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Alert on any emergency-account use with a documented test path; recent use after a meaningful dormant period for privileged accounts; account enablement followed by authentication; and rarely used accounts gaining roles, factors, or application credentials. Route governance findings separately from active-compromise alerts.

## Analyst Takeaway

Rarity becomes meaningful only when the account's purpose, privilege, and true activity sources are known.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
