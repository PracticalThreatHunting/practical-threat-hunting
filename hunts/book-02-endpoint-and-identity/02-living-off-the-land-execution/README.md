# Hunt 02 — Living-off-the-Land Execution

Book 2 companion implementation for Chapter 7 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Foundational-Intermediate
- **Estimated time:** 45-75 minutes
- **Primary telemetry:** Endpoint process, file, module, and network
- **ATT&CK:** T1218 - System Binary Proxy Execution; related sub-techniques
- **Primary skill:** Profiling legitimate binaries in abnormal relationships

## Hunt Hypothesis

If a legitimate Windows utility proxies malicious execution or content retrieval, at least one relationship should deviate from baseline: unusual parent, user-writable target path, remote content, uncommon export or argument form, rare signer, unexpected child process, or external network connection.

## Required Telemetry

- Process creation with full command line and ancestry.
- File path, hash, signer, and prevalence for referenced content.
- Network connections and DNS associated with the utility.
- Module or image-load events where available.
- File origin or download context when available.

## Reference Queries

- [Microsoft Defender XDR KQL](queries/01-microsoft-defender-xdr-kql.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Detect concrete abuse relationships: a trusted utility retrieving remote content, loading from a user-writable directory, launching an unexpected child, or running under an identity that never uses it. Maintain exceptions at the narrowest stable combination.

## Analyst Takeaway

The trusted binary is only one field. The parent, arguments, target, destination, user, and outcome determine whether its use is trustworthy.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
