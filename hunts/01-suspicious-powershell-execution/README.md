# Hunt 01 — Suspicious PowerShell Execution

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Foundational
- **Estimated time:** 30–60 minutes
- **Primary telemetry:** Endpoint process + optional script/network telemetry
- **ATT&CK:** T1059.001 — PowerShell
- **Primary skill:** Process context and command-line reasoning

## Scenario Summary

PowerShell is a legitimate administrative and automation tool, which is exactly why it is useful to adversaries. A hunt that simply searches for powershell.exe will drown in normal activity. The useful question is whether PowerShell is being launched in a context, with arguments, or with follow-on behavior that differs from the environment’s normal administrative patterns.

## Hunt Hypothesis

If an adversary uses PowerShell for execution, download, discovery, or in-memory activity, the endpoint should show one or more contextual anomalies: suspicious parent processes, encoded or obfuscated arguments, uncommon execution paths, network activity shortly after launch, or execution by users and systems that rarely use PowerShell.

## Query Implementations

- [Example KQL](queries/01-microsoft-defender-xdr.kql)
- [Normalized-field example](queries/01-splunk-normalized-process-hunt.spl)
- [Normalized-field example](queries/01-crowdstrike-normalized-process-hunt.logscale)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
