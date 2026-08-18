# Hunt 24 — Directory Replication and Domain Control Abuse

Book 2 companion implementation for Chapter 29 of *Practical Threat Hunting: Endpoint and Identity Threats*.

## Hunt Metadata

- **Difficulty:** Expert
- **Estimated time:** 120-240 minutes
- **Primary telemetry:** Domain controller Security and directory-service logs, identity sensor, endpoint and network
- **ATT&CK:** T1003.006 - DCSync; T1207 - Rogue Domain Controller
- **Primary skill:** Distinguishing legitimate replication from privilege abuse

## Hunt Hypothesis

If directory replication capability is abused and the relevant access or network records are available, activity may originate from a non-domain-controller system, an unexpected principal, or a newly changed rights relationship, followed by credential use, directory manipulation, or persistence.

## Required Telemetry

- Domain controller Security events, including directory-service access where configured.
- Subject principal, source host or address, object, access mask, properties, and logon ID.
- Directory replication topology and authoritative domain-controller inventory.
- Principals holding replication rights and the approved reason.
- Directory object and rights changes.
- Identity sensor detections or advanced-hunting events.
- Endpoint process, network connection, and logon evidence from the source.

## Reference Queries

- [Windows Security Review](queries/01-windows-security-review.kql)
- [Microsoft Defender XDR Schema-Discovery Pattern](queries/02-microsoft-defender-xdr-schema-discovery-pattern.kql)

## AI-Assisted Analysis

- [Evidence-bound analysis prompt](ai-prompt.md)

## Detection Opportunities

Prioritize replication rights granted to a new principal, 4662 replication access by a non-domain-controller identity, replication traffic from an unexpected host, directory topology changes outside change control, and replication activity followed by privileged credential use. Pair high-severity alerts with a tested domain-compromise response plan.

## Analyst Takeaway

Domain-control hunting demands topology, rights, endpoint, and directory evidence in one investigation.


## Validation Boundary

These files are reference implementations, not universal production detections. Confirm table and event availability, inspect representative raw records, validate field types and null behavior, tune the time window and thresholds, and test both benign and controlled-positive cases in the target environment.

See the [Book 2 technical source notes](../../../resources/book-02-source-notes.md) and the repository [disclaimer](../../../DISCLAIMER.md).
