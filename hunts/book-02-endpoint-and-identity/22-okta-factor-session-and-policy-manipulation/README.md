# Hunt 22 — Okta Factor, Session, and Policy Manipulation

Book 2 companion implementation for Chapter 27 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 90-180 minutes
- **Primary telemetry:** Okta System Log, factor and policy lifecycle, administrator actions, application access
- **ATT&CK:** T1556 - Modify Authentication Process; T1098 - Account Manipulation
- **Primary skill:** Reconstructing Okta transaction and actor relationships

## Hunt Hypothesis

If Okta controls are manipulated and the relevant System Log events are available, factor, session, policy, zone, token, or administrator events may be initiated by an unusual actor or client, fall outside the expected workflow, or be followed by access inconsistent with the affected identity's normal behavior.

## Required Telemetry

- `uuid`, `published`, `eventType`, `version`, and display message.
- Actor ID, type, alternate ID, and display name.
- Client IP, user agent, device, zone, and geographical context.
- Outcome result and reason.
- Target IDs, types, alternate IDs, and display names.
- Transaction, request, authentication context, security context, and debug context.
- Administrator, group, application, factor, session, API token, policy, and network-zone inventory.

## Reference Queries

- [Splunk SPL - Normalized Discovery Pattern](queries/01-splunk-spl-normalized-discovery-pattern.spl)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Prioritize factor reset followed by session creation, factor enrollment from a new client, policy weakening, network-zone changes that alter access, API-token creation by a rare administrator, and administrator assignment followed by sensitive changes. Keep transaction and raw-event context attached to alerts.

## Analyst Takeaway

Okta hunting is strongest when raw event structure is preserved and lifecycle actions are connected to the resulting session.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
