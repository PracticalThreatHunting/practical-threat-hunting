# Hunt 13 — Password Spraying and Distributed Authentication Failure

Book 2 companion implementation for Chapter 18 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Intermediate
- **Estimated time:** 60-120 minutes
- **Primary telemetry:** Entra ID sign-ins, Okta System Log, VPN and application authentication
- **ATT&CK:** T1110.003 - Password Spraying; T1078 - Valid Accounts
- **Primary skill:** Separating broad authentication pressure from ordinary user failure

## Hunt Hypothesis

If an actor is spraying credentials and the relevant events are collected, authentication telemetry may show an unusual many-user-to-one-source or many-source-to-one-user relationship, sometimes followed by a success from the same infrastructure, client pattern, autonomous system, or campaign window.

## Required Telemetry

- Timestamp, stable user identifier, username, source IP, result, and failure reason.
- Application, client, user agent, authentication protocol, and interactive status.
- Device identity, management state, trust state, geography, and conditional-access outcome where available.
- IP ownership or network category enrichment, with the enrichment time recorded.
- Successful sign-ins and post-authentication activity, not failures alone.
- Known scanners, identity tests, shared egress, VPN concentrators, and sanctioned red-team infrastructure.

## Reference Queries

- [Microsoft Sentinel KQL - Many Users from One Source](queries/01-microsoft-sentinel-kql-many-users-from-one-source.kql)
- [Microsoft Sentinel KQL - Distributed Attempts Against One User](queries/02-microsoft-sentinel-kql-distributed-attempts-against-one-user.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Use separate logic for concentrated and distributed spraying. Suppress only verified infrastructure and retain a success-after-pressure path with higher severity. Detection logic should support stable user IDs and campaign-level grouping rather than creating one alert per failed login.

## Analyst Takeaway

The useful unit of analysis is the authentication campaign, not the individual failure.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
