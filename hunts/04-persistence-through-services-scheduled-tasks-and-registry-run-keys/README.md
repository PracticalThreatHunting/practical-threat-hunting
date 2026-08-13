# Hunt 04 — Persistence Through Services, Scheduled Tasks, and Registry Run Keys

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Intermediate
- **Estimated time:** 60–90 minutes
- **Primary telemetry:** Process, service/task, registry, file telemetry
- **ATT&CK:** T1543.003, T1053.005, T1547.001
- **Primary skill:** Baseline-driven persistence hunting

## Scenario Summary

Services, scheduled tasks, and autorun registry locations are common persistence mechanisms because they are also legitimate mechanisms used by software deployment, management, and user applications. The hunting challenge is not finding these objects; it is identifying newly created or modified persistence whose creator, target path, execution context, or timing is inconsistent with expected administration.

## Hunt Hypothesis

If an adversary establishes persistence through a service, scheduled task, or run key, the endpoint should record a creation or modification event tied to a process and user, followed by execution of a target that is rare, unsigned, user-writable, externally retrieved, or otherwise inconsistent with the device’s normal software lifecycle.

## Query Implementations

- [Process-based KQL](queries/01-process-based.kql)
- [Registry pivot](queries/02-registry-pivot.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
