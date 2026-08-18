# Hunt 20 — OAuth Consent and High-Privilege Application Access

Book 2 companion implementation for Chapter 25 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 90-180 minutes
- **Primary telemetry:** Application consent, permission grants, service-principal audit, Graph and SaaS activity
- **ATT&CK:** T1098.003 - Additional Cloud Roles; T1550.001 - Application Access Token
- **Primary skill:** Evaluating permission, publisher, consenting actor, and resulting use

## Hunt Hypothesis

If OAuth consent or application permissions are abused and the relevant events are collected, audit logs may show a new or changed grant involving a rare application, high-impact permission, unusual consenting actor, or unverified publisher, followed by access to resources inconsistent with the application's purpose.

## Required Telemetry

- Application ID, service-principal ID, tenant ID, publisher and verification status.
- Consenting actor, target resource, delegated scopes, application roles, and consent type.
- Old and new permissions with grant timestamp and correlation ID.
- Application sign-ins, Graph activity, workload audit, and accessed resources.
- Application owner, business purpose, approval record, and credential inventory.
- User risk and sign-in context for the consenting actor.

## Reference Queries

- [Microsoft Sentinel KQL - Consent and Permission Changes](queries/01-microsoft-sentinel-kql-consent-and-permission-changes.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Prioritize new high-impact application permissions, admin consent by rare actors, permission expansion followed by immediate resource use, grant to a newly created service principal, consent after suspicious user authentication, and application access inconsistent with the stated purpose. Maintain a governed application inventory rather than an unowned allowlist.

## Analyst Takeaway

Consent is not the end of the hunt. Measure the application's effective access and what it used.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
