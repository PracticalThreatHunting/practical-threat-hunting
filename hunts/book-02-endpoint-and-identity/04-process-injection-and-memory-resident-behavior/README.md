# Hunt 04 — Process Injection and Memory-Resident Behavior

Book 2 companion implementation for Chapter 9 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 90-150 minutes
- **Primary telemetry:** EDR behavioral events, process access, memory, image load, thread activity
- **ATT&CK:** T1055 - Process Injection
- **Primary skill:** Reasoning from sensor-specific behavioral evidence

## Hunt Hypothesis

If code is injected into another process, the endpoint may expose suspicious process-access rights, remote memory allocation or writes, thread creation, executable memory transitions, image loads from unusual paths, or a trusted target process performing network or child-process activity that differs from its baseline.

## Required Telemetry

- EDR process-access and injection behavioral events with source and target processes.
- Process creation and termination.
- Module or image-load telemetry with path, hash, and signer.
- Network and child-process activity associated with the target.
- Optional memory-protection, call-stack, or sensor alert context.

## Reference Queries

- [Microsoft Defender XDR KQL - Schema-Discovery Pattern](queries/01-microsoft-defender-xdr-kql-schema-discovery-pattern.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

High-quality detections are sensor-specific. They may combine a process-access or injection event with a rare source, sensitive target, unsigned module, unexpected network activity, or suspicious ancestry. Keep the underlying event and source-target context available to responders.

## Analyst Takeaway

Process injection is a family of behaviors, not one string. Let the sensor evidence define what can be claimed.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
