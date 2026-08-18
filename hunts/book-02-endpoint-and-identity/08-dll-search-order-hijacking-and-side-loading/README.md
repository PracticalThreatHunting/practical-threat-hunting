# Hunt 08 — DLL Search-Order Hijacking and Side-Loading

Book 2 companion implementation for Chapter 13 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 90-180 minutes
- **Primary telemetry:** Module or image load, process, file, signer, prevalence
- **ATT&CK:** T1574.001 - Hijack Execution Flow: DLL
- **Primary skill:** Evaluating executable-module relationships

## Hunt Hypothesis

If an adversary abuses DLL loading, a trusted or expected executable should load an unsigned, rare, recently created, or user-writable module that is inconsistent with the executable's normal path, signer, version, and fleet prevalence.

## Required Telemetry

- Image-load or module-load events with executable and module paths.
- Signer, certificate, hash, version, and prevalence.
- Process ancestry and command line.
- File creation and first-seen time for the module.
- Device role and installed-software inventory.

## Reference Queries

- [Microsoft Defender XDR KQL - Schema-Dependent Pattern](queries/01-microsoft-defender-xdr-kql-schema-dependent-pattern.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Detect high-risk relationships: a trusted executable loading a newly created, rare, unsigned, or user-writable module; a module signer inconsistent with the host application; or side-loading adjacent to external communication and persistence.

## Analyst Takeaway

Trust applies to the executable-module relationship, not to either file in isolation.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
