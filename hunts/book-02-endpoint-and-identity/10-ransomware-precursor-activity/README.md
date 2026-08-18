# Hunt 10 — Ransomware Precursor Activity

Book 2 companion implementation for Chapter 15 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 90-180 minutes
- **Primary telemetry:** Process, file, share, recovery, service, authentication
- **ATT&CK:** T1486 - Data Encrypted for Impact; precursor behaviors across discovery, impairment, and lateral movement
- **Primary skill:** Detecting converging activity before encryption

## Hunt Hypothesis

If an adversary is preparing enterprise-wide encryption, multiple precursor behaviors should converge across high-value accounts and devices: recovery deletion, backup or service changes, security impairment, remote execution, share access, tool staging, and unusual authentication spread.

## Required Telemetry

- Process execution on endpoints and servers.
- File creation, rename, high-volume modification, and extension patterns.
- Backup, recovery, shadow-copy, and service events.
- SMB, RDP, WinRM, WMI, and remote-service activity.
- Authentication across devices and privileged accounts.
- EDR alerts and security-control changes.

## Reference Queries

- [Microsoft Defender XDR KQL - Recovery and Backup Changes](queries/01-microsoft-defender-xdr-kql-recovery-and-backup-changes.kql)
- [Cross-Device Spread Pattern](queries/02-cross-device-spread-pattern.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Build layered analytics: recovery deletion, broad service stopping, high-rate remote execution, privileged account fan-out, mass share access, and security impairment. Correlate them into an incident-level analytic when possible.

## Analyst Takeaway

Ransomware is a sequence. Detecting the preparation is more valuable than naming the encryptor after impact begins.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
