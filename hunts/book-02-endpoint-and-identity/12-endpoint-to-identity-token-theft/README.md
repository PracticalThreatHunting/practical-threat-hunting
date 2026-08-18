# Hunt 12 — Endpoint-to-Identity Token Theft

Book 2 companion implementation for Chapter 17 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 90-180 minutes
- **Primary telemetry:** Endpoint process/file, browser or token artifacts, sign-in, session, application activity
- **ATT&CK:** T1528 - Steal Application Access Token; T1539 - Steal Web Session Cookie
- **Primary skill:** Correlating local artifact access with remote session use

## Hunt Hypothesis

If session or token material is stolen from an endpoint and replayed elsewhere, endpoint evidence may show access to browser or application session stores, while identity evidence shows a session, client, IP, device, or resource pattern that does not align with the user's established device and authentication history.

## Required Telemetry

- Endpoint access or staging of browser and application session artifacts.
- Process, file, archive, and exfiltration context.
- Sign-in records with device, client, IP, session, correlation, and authentication details.
- Application or Graph activity showing token use.
- Session revocation, factor, and password-change events.

## Reference Queries

- [Microsoft Sentinel KQL - Device and IP Discontinuity Pattern](queries/01-microsoft-sentinel-kql-device-and-ip-discontinuity-pattern.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Detection may combine endpoint access to session stores with a new identity session, suspicious resource activity, impossible device transitions, or post-authentication behavior inconsistent with the user's baseline. This is often best represented as a correlated incident rather than a single-event alert.

## Analyst Takeaway

Token theft is where endpoint compromise becomes identity compromise without a clean new-login signal.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
