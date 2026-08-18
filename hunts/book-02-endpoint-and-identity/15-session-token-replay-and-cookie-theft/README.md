# Hunt 15 — Session Token Replay and Cookie Theft

Book 2 companion implementation for Chapter 20 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 90-180 minutes
- **Primary telemetry:** Sign-in, session, application activity, endpoint browser and token artifacts
- **ATT&CK:** T1539 - Steal Web Session Cookie; T1528 - Steal Application Access Token
- **Primary skill:** Distinguishing session continuity from legitimate reauthentication

## Hunt Hypothesis

If an existing session or token is replayed, available records may exhibit a discontinuity in device, client, network, geography, or resource access while retaining evidence of session continuity or lacking a corresponding fresh authentication sequence.

## Required Telemetry

- Interactive and non-interactive sign-ins.
- Session, token, request, correlation, and application identifiers where exposed.
- Authentication protocol, token type, client, device, IP, and location.
- Microsoft 365, Graph, SaaS, or application activity produced by the token.
- Endpoint process and file activity involving browser profiles, token caches, or session databases.
- Session revocation and credential-change timestamps.

## Reference Queries

- [Microsoft Sentinel KQL - Short-Window Session Discontinuity](queries/01-microsoft-sentinel-kql-short-window-session-discontinuity.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Prioritize correlations: browser or token-store access followed by new session infrastructure, activity after password reset without revocation, sensitive actions from a session with abrupt device change, or a token used across incompatible client contexts. Detection should preserve the original authentication and resource records.

## Analyst Takeaway

To find token replay, follow the session into the resource and back to the endpoint.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
