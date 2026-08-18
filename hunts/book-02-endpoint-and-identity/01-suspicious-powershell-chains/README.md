# Hunt 01 — Suspicious PowerShell Chains

Book 2 companion implementation for Chapter 6 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Foundational-Intermediate
- **Estimated time:** 45-75 minutes
- **Primary telemetry:** Endpoint process, PowerShell operational log, network, file
- **ATT&CK:** T1059.001 - PowerShell
- **Primary skill:** Process-chain and script-context reasoning

## Hunt Hypothesis

If an adversary uses PowerShell for download, discovery, credential access, defense impairment, persistence, or in-memory execution, the endpoint should expose one or more contextual deviations: a risky parent process, encoded or obfuscated content, uncommon execution options, access to sensitive processes or registry areas, external communication, payload creation, or execution by an identity and device that rarely use PowerShell.

## Required Telemetry

- Process creation with full path, command line, parent or initiating process, account, device, process ID, and hash.
- PowerShell Script Block Logging where approved and configured.
- Network events associated with the initiating process.
- File creation and modification associated with the process chain.
- Optional AMSI, EDR behavioral events, signer, prevalence, and process integrity level.

## Reference Queries

- [Establish Normal](queries/01-establish-normal.kql)
- [Microsoft Defender XDR KQL](queries/02-microsoft-defender-xdr-kql.kql)
- [Splunk SPL - Normalized Example](queries/03-splunk-spl-normalized-example.spl)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Stable detections combine PowerShell behavior with context: high-risk parents, rare user-device pairs, suspicious script constructs, unexpected network access, payload creation, security-setting changes, or access to sensitive processes. Separate well-understood management patterns through narrow, owner-approved exceptions rather than excluding PowerShell broadly.

## Analyst Takeaway

PowerShell becomes meaningful when the chain explains intent. Hunt the parent, script, identity, destination, and outcome together.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
