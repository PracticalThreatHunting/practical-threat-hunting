# Hunt 16 — New Geography, Proxy, and Device Mismatch

Book 2 companion implementation for Chapter 21 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate
- **Estimated time:** 60-120 minutes
- **Primary telemetry:** Sign-ins, device inventory, network enrichment, application activity
- **ATT&CK:** T1078 - Valid Accounts; T1090 - Proxy
- **Primary skill:** Testing contextual inconsistency without overtrusting geolocation

## Hunt Hypothesis

If an account is used from attacker-controlled infrastructure, a sign-in or application session may introduce a new combination of geography, network category, device, client, application, and authentication method that is inconsistent with the user's history and surrounding activity.

## Required Telemetry

- Stable user ID, timestamp, IP, location, application, result, and interaction type.
- Device ID, operating system, browser, management and trust state.
- Network enrichment such as ASN, organization, hosting, proxy, VPN, or residential classification.
- User travel, approved VPN, remote desktop, virtual desktop, and secure web gateway context.
- Authentication method and conditional-access result.
- Application actions after the sign-in.

## Reference Queries

- [Microsoft Sentinel KQL - First-Seen Context](queries/01-microsoft-sentinel-kql-first-seen-context.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Prefer combinations over single anomalies: new country plus new device plus sensitive action; new hosting network plus weak authentication; new client plus factor change; or rapid context transition within one session. Maintain allowlists as governed data with owners and expiration dates.

## Analyst Takeaway

Location is a clue. Device, authentication, and action context determine whether it matters.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
