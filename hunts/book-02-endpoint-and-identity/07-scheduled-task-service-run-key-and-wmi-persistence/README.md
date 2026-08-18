# Hunt 07 — Scheduled Task, Service, Run-Key, and WMI Persistence

Book 2 companion implementation for Chapter 12 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate
- **Estimated time:** 75-120 minutes
- **Primary telemetry:** Process, scheduled task, service, registry, WMI, file
- **ATT&CK:** T1053.005, T1543.003, T1547.001, T1546.003
- **Primary skill:** Comparing persistence changes with ownership and prevalence

## Hunt Hypothesis

If an adversary establishes Windows persistence, the environment should expose a new or modified task, service, startup entry, or WMI subscription whose creator, target path, command, account, trigger, or timing deviates from normal software and administrative patterns.

## Required Telemetry

- Scheduled-task create, update, and execution events.
- Service installation and modification events.
- Registry changes to startup locations.
- WMI query, subscription, provider, or process telemetry.
- Process creation and file activity for the referenced target.
- Change-management and software-deployment context.

## Reference Queries

- [Microsoft Defender XDR KQL - Registry Startup Changes](queries/01-microsoft-defender-xdr-kql-registry-startup-changes.kql)
- [Microsoft Defender XDR KQL - Service and Task Discovery](queries/02-microsoft-defender-xdr-kql-service-and-task-discovery.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Detect persistence creation when the target is in a user-writable path, the creator is rare, the command contains a risky interpreter or remote reference, or a privileged execution context is paired with an untrusted target. Track object modifications as well as creation.

## Analyst Takeaway

Persistence becomes suspicious when the object cannot be explained by a trusted owner, target, creation path, and execution context.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
