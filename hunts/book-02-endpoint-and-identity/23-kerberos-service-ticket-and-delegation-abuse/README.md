# Hunt 23 — Kerberos Service Ticket and Delegation Abuse

Book 2 companion implementation for Chapter 28 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 90-180 minutes
- **Primary telemetry:** Windows Security, domain controller, identity sensor, service-account inventory
- **ATT&CK:** T1558 - Steal or Forge Kerberos Tickets; T1558.003 - Kerberoasting
- **Primary skill:** Interpreting ticket relationships and service-account context

## Hunt Hypothesis

If Kerberos is being abused and the relevant domain-controller events are collected, ticket telemetry may show an unusual account-to-service relationship, service-ticket fan-out, weak or unexpected encryption, atypical source host, delegation path, or ticket use inconsistent with account and service baselines.

## Required Telemetry

- Domain controller Security events for TGT and service-ticket requests.
- User, service, source address, source workstation, domain, result, and encryption type.
- Ticket options, status or failure code, logon GUID, and correlation fields where available.
- Service principal names and authoritative service-account inventory.
- Delegation settings, sensitivity flags, group memberships, and password-management controls.
- Endpoint process, logon, and network evidence from the requesting host.

## Reference Queries

- [Microsoft Sentinel KQL - Service Ticket Fan-Out](queries/01-microsoft-sentinel-kql-service-ticket-fan-out.kql)
- [Microsoft Sentinel KQL - Encryption Review](queries/02-microsoft-sentinel-kql-encryption-review.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

High-value combinations include rare workstation requesting many high-value service tickets, unexpected legacy encryption for an account that normally uses stronger types, ticket requests from a newly observed endpoint, abuse-prone delegation changes, and ticket anomalies followed by service logon or privileged access. Inventory quality is part of detection quality.

## Analyst Takeaway

Kerberos anomalies become actionable when ticket behavior is anchored to the requesting endpoint and the service account's intended role.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
