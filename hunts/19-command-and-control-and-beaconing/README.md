# Hunt 19 — Command-and-Control and Beaconing

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced
- **Estimated time:** 75–150 minutes
- **Primary telemetry:** Endpoint network + DNS/proxy/network metadata
- **ATT&CK:** T1071.001, T1071.004
- **Primary skill:** Temporal and rarity analysis

## Scenario Summary

Command-and-control traffic can be loud, but mature malware often blends into ordinary web or DNS activity. Beaconing may use common ports, HTTPS, content-delivery networks, domain-fronting-like patterns, or low-frequency callbacks. Hunting therefore benefits from combining temporal regularity with process context and destination rarity.

## Hunt Hypothesis

If a compromised process maintains command-and-control, network telemetry may show repeated connections from the same process/device to a rare or low-prevalence destination with unusual periodicity, small transfer patterns, or a process/network relationship not normally observed on the host.

## Query Implementations

- [Defender XDR KQL — rare destination/process pairs](queries/01-defender-xdr-rare-destination-process-pairs.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
