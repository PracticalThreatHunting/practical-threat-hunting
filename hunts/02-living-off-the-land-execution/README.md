# Hunt 02 — Living-off-the-Land Execution

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Foundational–Intermediate
- **Estimated time:** 45–75 minutes
- **Primary telemetry:** Endpoint process + network/file telemetry
- **ATT&CK:** T1218 — System Binary Proxy Execution (plus related techniques)
- **Primary skill:** Contextual analysis of legitimate binaries

## Scenario Summary

Adversaries frequently abuse legitimate operating-system binaries because those tools are already present, trusted, and often permitted by application controls. Utilities such as rundll32.exe, regsvr32.exe, mshta.exe, certutil.exe, bitsadmin.exe, wmic.exe, and scripting hosts can execute code, retrieve content, manipulate configuration, or proxy execution. A filename-only hunt will either miss subtle abuse or produce unmanageable noise.

## Hunt Hypothesis

If a legitimate system binary is being abused for malicious execution, its command line, parent process, target file or URL, user context, or follow-on activity should differ from the patterns associated with normal software installation, administration, and operating-system behavior.

## Query Implementations

- [Microsoft Defender XDR KQL](queries/01-microsoft-defender-xdr.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
