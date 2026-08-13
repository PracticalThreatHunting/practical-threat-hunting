# Hunt 23 — AI API Key and Service Identity Compromise

Companion resources for the corresponding hands-on hunt in *Practical Threat Hunting: Modern Techniques for the AI-Augmented SOC*.

## Hunt Snapshot

- **Difficulty:** Advanced
- **Estimated time:** 90–150 minutes
- **Primary telemetry:** AI-provider audit/usage, secrets manager, IAM/IdP, cloud logs, billing/usage
- **Frameworks:** MITRE ATT&CK credential abuse + MITRE ATLAS enterprise AI
- **Primary skill:** Baselining non-human AI identities

## Scenario Summary

A model-provider bill spikes overnight and a production AI application begins calling an unfamiliar model from an unexpected region. The application uses an API key stored in a secrets platform and a cloud workload identity for surrounding resources. The hunt must determine whether this is a deployment change, leaked secret, compromised workload, or intentional misuse.

## Hunt Hypothesis

An AI API key, token, service account, managed identity, or workload credential is being used outside its expected application, network, region, model set, or volume profile.

## Query Implementations

- [Illustrative Entra service-principal baseline — confirm table availability and schema in your tenant](queries/01-sentinel-service-principal-baseline.kql)
- [Provider-neutral detection concept](queries/01-usage-anomaly-pseudocode.txt)
- [Microsoft Defender XDR — service-principal source anomaly](queries/02-microsoft-defender-xdr-service-principal-source-anomaly.kql)
- [AI-assisted hunt prompts](ai-prompts.md)

## Validation Before Use

- Confirm the referenced telemetry exists and is retained for the required time window.
- Verify every table, field, join key, and event semantic in your tenant.
- Establish normal behavior before assigning significance to rarity.
- Run the query narrowly first and inspect raw events before increasing scope.
- Treat thresholds as starting points, not universal truth.
- Do not promote hunt logic directly to production detection without historical and controlled validation.

See the repository [DISCLAIMER.md](../../DISCLAIMER.md) for defensive-use and implementation guidance.
