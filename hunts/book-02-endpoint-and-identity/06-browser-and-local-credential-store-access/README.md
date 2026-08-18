# Hunt 06 — Browser and Local Credential Store Access

Book 2 companion implementation for Chapter 11 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate
- **Estimated time:** 60-120 minutes
- **Primary telemetry:** Process, file access, browser-profile artifacts, DPAPI context, sign-in
- **ATT&CK:** T1555 - Credentials from Password Stores; related sub-techniques
- **Primary skill:** Connecting local data access with session and identity activity

## Hunt Hypothesis

If an unauthorized process accesses local credential or session stores, the endpoint may show a non-browser process reading, copying, archiving, or staging browser-profile and application-credential files, followed by remote sign-ins, token use, or application access inconsistent with the user's device and network history.

## Required Telemetry

- File access, creation, copy, and archive activity for browser and application profiles.
- Process creation and ancestry.
- Signer, hash prevalence, account, and device role.
- Browser process and profile context.
- Identity sign-in, device, session, IP, and application activity.

## Reference Queries

- [Microsoft Defender XDR KQL - File Creation and Staging Pattern](queries/01-microsoft-defender-xdr-kql-file-creation-and-staging-pattern.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Detect rare non-browser access to protected profile artifacts, bulk copying or archiving of browser data, and credential-store access followed by remote session anomalies. Keep privacy and data-handling requirements explicit because this telemetry can expose sensitive user information.

## Analyst Takeaway

The endpoint shows access to session material; the identity platform shows whether that material was used. Investigate both.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
