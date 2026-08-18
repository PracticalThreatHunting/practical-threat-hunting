# Hunt 21 — Service Principal and Application Credential Abuse

Book 2 companion implementation for Chapter 26 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 90-180 minutes
- **Primary telemetry:** Service-principal sign-ins, application audit, credential inventory, workload activity
- **ATT&CK:** T1078.004 - Cloud Accounts; T1098.001 - Additional Cloud Credentials
- **Primary skill:** Baselining non-human identity behavior

## Hunt Hypothesis

If a service principal or application credential is abused, sign-in or resource records may introduce a new source, resource, tenant, time pattern, credential relationship, or permission use inconsistent with the workload's documented operation.

## Required Telemetry

- Application and service-principal immutable IDs.
- Sign-in timestamp, source IP, resource, tenant, result, credential or authentication context where exposed.
- Secret, certificate, key, federated credential, and owner inventory with creation and expiration.
- Application permissions and role assignments.
- Deployment platform, expected egress, schedule, environment, and business owner.
- Graph, Azure, Microsoft 365, SaaS, and cloud resource activity.

## Reference Queries

- [Microsoft Sentinel KQL - Service Principal Sign-In Baseline](queries/01-microsoft-sentinel-kql-service-principal-sign-in-baseline.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Useful signals include application credential addition by an unexpected actor, new credential followed by use from new infrastructure, access to a new resource, activity outside deployment patterns, cross-tenant use, or high-impact Graph actions by a rarely used service principal. Route ownerless-identity findings into governance even when compromise is not established.

## Analyst Takeaway

Workload identity hunting starts with architecture and ownership, not with a human-user anomaly score.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
