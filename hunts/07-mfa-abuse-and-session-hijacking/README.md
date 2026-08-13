# Hunt 07 — MFA Abuse and Session Hijacking

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate–Advanced
- **Estimated time:** 60–120 minutes
- **Primary telemetry:** Identity sign-ins + M365/SaaS activity
- **ATT&CK:** T1621 — MFA Request Generation; T1539 — Steal Web Session Cookie
- **Primary skill:** Authentication-to-session correlation

## Scenario Summary

MFA reduces credential-only compromise, but it does not make authentication telemetry simple. Attackers may generate repeated MFA requests, manipulate users into approving a sign-in, steal session cookies through adversary-in-the-middle phishing, or reuse a valid session after authentication. A successful MFA event therefore proves that an authentication requirement was satisfied; it does not by itself prove the user intentionally initiated the session.

## Hunt Hypothesis

If MFA is being abused or an authenticated session is stolen, identity and application telemetry may show abnormal MFA sequences, sign-in context changes, resource access from infrastructure not associated with the original authentication, or sensitive activity that is inconsistent with the user’s normal device and session behavior.

## Query Implementations

- [Microsoft Sentinel KQL — MFA pressure pattern](queries/01-microsoft-sentinel-mfa-pressure-pattern.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
