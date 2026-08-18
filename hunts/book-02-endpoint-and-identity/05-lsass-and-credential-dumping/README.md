# Hunt 05 — LSASS and Credential Dumping

Book 2 companion implementation for Chapter 10 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate-Advanced
- **Estimated time:** 60-120 minutes
- **Primary telemetry:** Process access, file creation, registry, EDR, command line
- **ATT&CK:** T1003 and T1003.001 - OS Credential Dumping: LSASS Memory
- **Primary skill:** Correlating sensitive-process access with credential-use outcomes

## Hunt Hypothesis

If an adversary attempts to collect operating-system credential material, the endpoint should show one or more of the following: unusual access to LSASS or security-sensitive processes, dump-file creation, registry hive access or export, suspicious command-line patterns, security-control changes, or subsequent authentication from another device using the affected identity.

## Required Telemetry

- Process access to LSASS or equivalent sensor behavioral events.
- Process creation and full command line.
- File creation for dump or hive artifacts.
- Registry access or modification where available.
- EDR alerts, security-control changes, and memory collection.
- Authentication and lateral-movement telemetry after the suspected access.

## Reference Queries

- [Microsoft Defender XDR KQL - Candidate Process and File Patterns](queries/01-microsoft-defender-xdr-kql-candidate-process-and-file-patterns.kql)
- [Microsoft Defender XDR KQL - Candidate Process and File Patterns](queries/02-microsoft-defender-xdr-kql-candidate-process-and-file-patterns-2.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Detect unusual access to LSASS, sensitive hive exports, dump creation by unexpected processes, credential-related command lines, or credential access combined with security impairment. The strongest detections connect endpoint access to follow-on use of the affected identity.

## Analyst Takeaway

Credential dumping changes the scope from one host to every identity that may have been exposed on that host.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
