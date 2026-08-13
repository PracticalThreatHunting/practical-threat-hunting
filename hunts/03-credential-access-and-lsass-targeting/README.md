# Hunt 03 — Credential Access and LSASS Targeting

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate
- **Estimated time:** 45–90 minutes
- **Primary telemetry:** Endpoint process, file, security/EDR telemetry
- **ATT&CK:** T1003.001 — LSASS Memory
- **Primary skill:** Recognizing credential-access preparation and artifacts

## Scenario Summary

Windows credential-access activity often targets the Local Security Authority Subsystem Service (LSASS) or attempts to create process memory dumps that can be analyzed for credentials. Modern EDR products may block or alert on obvious tools, but hunters should still look for the surrounding behaviors: dump utilities, suspicious rundll32 use, newly created dump files, unusual process access to LSASS, and follow-on authentication activity.

## Hunt Hypothesis

If an adversary attempts to extract credentials from LSASS, endpoint telemetry should show a process or command sequence interacting with LSASS, creating a dump or equivalent artifact, invoking known dump mechanisms, or producing follow-on account activity inconsistent with the original user or device.

## Query Implementations

- [Microsoft Defender XDR KQL](queries/01-microsoft-defender-xdr.kql)
- [Optional dump-file pivot](queries/02-optional-dump-file-pivot.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
