# Hunt 19 — Account Creation, Re-Enablement, and Recovery Changes

Book 2 companion implementation for Chapter 24 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate
- **Estimated time:** 60-120 minutes
- **Primary telemetry:** Directory audit, authentication, HR and identity-governance records
- **ATT&CK:** T1136 - Create Account; T1098 - Account Manipulation
- **Primary skill:** Correlating lifecycle change with first use

## Hunt Hypothesis

If an account lifecycle process is abused, available audit and governance records may show a creation, enablement, recovery, ownership, or credential event performed by an unusual actor, lacking an expected governance record, or followed by suspicious authentication and access.

## Required Telemetry

- Audit timestamp, operation, actor user or application, target ID, result, and correlation ID.
- Old and new values for account status, ownership, recovery, and credential properties.
- Authoritative identity status, manager, sponsor, account type, and lifecycle dates.
- Role, group, application, and resource assignments.
- First successful authentication with source, device, client, and method.
- Administrative and data-access actions after first use.

## Reference Queries

- [Microsoft Sentinel KQL - Lifecycle Change Discovery](queries/01-microsoft-sentinel-kql-lifecycle-change-discovery.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

High-value sequences include enablement followed rapidly by sign-in, new account followed by privileged assignment, recovery change followed by authentication from new infrastructure, lifecycle change by a rare application, and creation outside the authoritative provisioning path. Monitor deleted-and-recreated objects by immutable ID, not reused display name.

## Analyst Takeaway

An account change becomes security evidence when it is tied to the actor, approval path, privilege, and first use.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
