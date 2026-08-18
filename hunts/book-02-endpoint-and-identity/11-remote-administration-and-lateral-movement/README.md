# Hunt 11 — Remote Administration and Lateral Movement

Book 2 companion implementation for Chapter 16 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate-Advanced
- **Estimated time:** 90-150 minutes
- **Primary telemetry:** Authentication, network, process, service, task, remote shell
- **ATT&CK:** T1021 - Remote Services; T1078 - Valid Accounts
- **Primary skill:** Correlating source authentication with destination execution

## Hunt Hypothesis

If an adversary moves laterally, the environment should show a source account or device accessing an unusual destination or an unusual number of devices, followed by remote-service execution, a new service or task, a remote shell, or child processes inconsistent with normal administration.

## Required Telemetry

- Source and destination authentication with account, IP, device, and logon type.
- Network connections for remote-service protocols.
- Destination process creation and ancestry.
- Service, scheduled-task, WMI, and remote-shell events.
- Privileged-token and explicit-credential events where available.
- Asset role and administrative ownership.

## Reference Queries

- [Microsoft Defender XDR KQL - Account Fan-Out](queries/01-microsoft-defender-xdr-kql-account-fan-out.kql)
- [Microsoft Defender XDR KQL - Destination Follow-On](queries/02-microsoft-defender-xdr-kql-destination-follow-on.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Detect new source-account-destination triples, privileged fan-out, remote execution from non-management endpoints, suspicious destination process ancestry, and lateral movement adjacent to credential access. Exceptions should encode approved source, account, destination class, protocol, and time context.

## Analyst Takeaway

Lateral movement is proven by the chain from source authentication to destination action, not by a remote port alone.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
