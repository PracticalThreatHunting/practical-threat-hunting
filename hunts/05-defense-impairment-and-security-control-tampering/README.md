# Hunt 05 — Defense Impairment and Security-Control Tampering

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate
- **Estimated time:** 45–90 minutes
- **Primary telemetry:** Endpoint process + security product/audit telemetry
- **ATT&CK:** T1685 — Disable or Modify Tools; T1685.005 — Clear Windows Event Logs
- **Primary skill:** Recognizing attempts to reduce defender visibility

## Scenario Summary

Attackers who expect endpoint and logging controls may try to weaken them before continuing. In ATT&CK v19, this family of behavior is represented under the Defense Impairment tactic, including current techniques such as Disable or Modify Tools and its log-focused sub-techniques. Common behaviors include adding antivirus exclusions, disabling security services, clearing logs, changing audit settings, modifying firewall rules, stopping monitoring agents, or tampering with backup and recovery settings. These actions can also occur during legitimate maintenance, so authorization and sequence matter.

## Hunt Hypothesis

If an adversary attempts defense impairment, security-relevant configuration changes or process commands should occur outside normal administrative workflows and often cluster around other suspicious execution, credential access, or lateral movement.

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
