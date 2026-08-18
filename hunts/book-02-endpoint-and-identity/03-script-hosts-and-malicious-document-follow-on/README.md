# Hunt 03 — Script Hosts and Malicious Document Follow-On

Book 2 companion implementation for Chapter 8 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate
- **Estimated time:** 60-90 minutes
- **Primary telemetry:** Process ancestry, file origin, script, network, email or browser context
- **ATT&CK:** T1204 - User Execution; T1059 - Command and Scripting Interpreter
- **Primary skill:** Reconstructing multi-generation process chains

## Hunt Hypothesis

If user-delivered content initiates malicious execution, endpoint telemetry should show an unusual ancestry chain from a browser, mail client, Office application, archive utility, PDF reader, or mounted-content process into a shell, interpreter, script host, or signed proxy binary, followed by network, file, persistence, or credential activity.

## Required Telemetry

- Process creation with at least two generations of ancestry.
- File creation and origin path, including downloads and temporary extraction locations.
- Mark-of-the-Web or zone information where available.
- Network events associated with the child chain.
- Optional email, browser, archive, and removable-media context.

## Reference Queries

- [Microsoft Defender XDR KQL](queries/01-microsoft-defender-xdr-kql.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Candidate detections include high-risk Office-to-interpreter pairs, archive-tool-to-script-host chains, browser-to-LOLBin execution from a downloaded path, and content-handler chains that immediately contact a rare external destination. Detection should preserve the source file and ancestry so responders can understand the initiating event.

## Analyst Takeaway

Malicious execution often looks ordinary one process at a time. The multi-generation chain tells the story.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
