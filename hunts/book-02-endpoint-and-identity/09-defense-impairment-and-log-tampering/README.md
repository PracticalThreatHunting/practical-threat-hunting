# Hunt 09 — Defense Impairment and Log Tampering

Book 2 companion implementation for Chapter 14 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate
- **Estimated time:** 60-120 minutes
- **Primary telemetry:** Security-control events, process, registry, service, audit policy
- **ATT&CK:** T1685 - Disable or Modify Tools; T1685.001 - Disable or Modify Windows Event Log; T1685.005 - Clear Windows Event Logs
- **Primary skill:** Distinguishing approved administration from adversary control reduction

## Hunt Hypothesis

If an adversary impairs endpoint defenses, telemetry should show an unexpected security-setting, service, registry, command, or log event initiated by an unusual account or process, often shortly before additional execution, credential access, lateral movement, or destructive activity.

## Required Telemetry

- Defender or security-product configuration and tamper events.
- Process creation for management commands and scripts.
- Service stop, start, deletion, and configuration changes.
- Registry changes to security settings.
- Windows events for audit-policy changes and log clearing.
- Change-management and support context.

## Reference Queries

- [Microsoft Defender XDR KQL](queries/01-microsoft-defender-xdr-kql.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Alert on protection disablement, exclusions affecting broad or sensitive paths, sensor service changes, audit clearing, and policy modification outside approved management channels. Increase severity when impairment precedes credential access, ransomware precursors, or lateral movement.

## Analyst Takeaway

Defense changes are meaningful when the actor, scope, timing, and follow-on activity cannot be reconciled with approved operations.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
