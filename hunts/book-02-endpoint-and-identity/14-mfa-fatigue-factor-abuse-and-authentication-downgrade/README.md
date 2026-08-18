# Hunt 14 — MFA Fatigue, Factor Abuse, and Authentication Downgrade

Book 2 companion implementation for Chapter 19 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Advanced
- **Estimated time:** 75-150 minutes
- **Primary telemetry:** Authentication details, factor lifecycle, help-desk changes, policy audit
- **ATT&CK:** T1621 - Multi-Factor Authentication Request Generation; T1556 - Modify Authentication Process
- **Primary skill:** Reconstructing the complete factor sequence

## Hunt Hypothesis

If MFA is being abused and the relevant events are collected, a user's records may show an unusual concentration of denied, timed-out, or interrupted challenges; a factor or recovery change near the activity; or a successful authentication whose method, device, or protocol is inconsistent with the user's baseline.

## Required Telemetry

- Authentication step details, methods, results, requirement, and protocol.
- Factor enrollment, reset, removal, activation, and recovery events.
- Help-desk or administrator action with actor and target identities.
- Conditional-access and sign-on policy outcomes.
- Session creation, device, IP, client, application, and post-authentication activity.
- Voice, SMS, push, number-matching, passkey, certificate, and hardware-key distinctions where available.

## Reference Queries

- [Microsoft Sentinel KQL - Authentication Step Review](queries/01-microsoft-sentinel-kql-authentication-step-review.kql)
- [Microsoft Sentinel KQL - Factor and Recovery Changes](queries/02-microsoft-sentinel-kql-factor-and-recovery-changes.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Useful signals include repeated challenges followed by success, factor enrollment soon after suspicious primary authentication, factor reset by a rare help-desk actor, recovery changes for privileged accounts, and authentication-method downgrade. Correlated sequences should outrank raw prompt counts.

## Analyst Takeaway

MFA abuse is a sequence problem: reconstruct the proof path from password to session.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
