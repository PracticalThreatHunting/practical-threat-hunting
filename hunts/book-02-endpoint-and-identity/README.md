# Book 2 Hunts — Endpoint and Identity Threats

This directory contains the updateable implementation layer for the 24 hunts in *Practical Threat Hunting: Endpoint and Identity Threats*. The printed book teaches the investigation method; these files carry query examples, AI-analysis prompts, source links, and technical notes that can change with platform schemas.

## Hunt Index

| Hunt | Focus | Difficulty |
|---:|---|---|
| 01 | [Suspicious PowerShell Chains](01-suspicious-powershell-chains/README.md) | Foundational-Intermediate |
| 02 | [Living-off-the-Land Execution](02-living-off-the-land-execution/README.md) | Foundational-Intermediate |
| 03 | [Script Hosts and Malicious Document Follow-On](03-script-hosts-and-malicious-document-follow-on/README.md) | Intermediate |
| 04 | [Process Injection and Memory-Resident Behavior](04-process-injection-and-memory-resident-behavior/README.md) | Advanced |
| 05 | [LSASS and Credential Dumping](05-lsass-and-credential-dumping/README.md) | Intermediate-Advanced |
| 06 | [Browser and Local Credential Store Access](06-browser-and-local-credential-store-access/README.md) | Intermediate |
| 07 | [Scheduled Task, Service, Run-Key, and WMI Persistence](07-scheduled-task-service-run-key-and-wmi-persistence/README.md) | Intermediate |
| 08 | [DLL Search-Order Hijacking and Side-Loading](08-dll-search-order-hijacking-and-side-loading/README.md) | Advanced |
| 09 | [Defense Impairment and Log Tampering](09-defense-impairment-and-log-tampering/README.md) | Intermediate |
| 10 | [Ransomware Precursor Activity](10-ransomware-precursor-activity/README.md) | Advanced |
| 11 | [Remote Administration and Lateral Movement](11-remote-administration-and-lateral-movement/README.md) | Intermediate-Advanced |
| 12 | [Endpoint-to-Identity Token Theft](12-endpoint-to-identity-token-theft/README.md) | Advanced |
| 13 | [Password Spraying and Distributed Authentication Failure](13-password-spraying-and-distributed-authentication-failure/README.md) | Intermediate |
| 14 | [MFA Fatigue, Factor Abuse, and Authentication Downgrade](14-mfa-fatigue-factor-abuse-and-authentication-downgrade/README.md) | Advanced |
| 15 | [Session Token Replay and Cookie Theft](15-session-token-replay-and-cookie-theft/README.md) | Advanced |
| 16 | [New Geography, Proxy, and Device Mismatch](16-new-geography-proxy-and-device-mismatch/README.md) | Intermediate |
| 17 | [Dormant, Break-Glass, and Rarely Used Account Abuse](17-dormant-break-glass-and-rarely-used-account-abuse/README.md) | Intermediate |
| 18 | [Privileged Role and Group Escalation](18-privileged-role-and-group-escalation/README.md) | Advanced |
| 19 | [Account Creation, Re-Enablement, and Recovery Changes](19-account-creation-re-enablement-and-recovery-changes/README.md) | Intermediate |
| 20 | [OAuth Consent and High-Privilege Application Access](20-oauth-consent-and-high-privilege-application-access/README.md) | Advanced |
| 21 | [Service Principal and Application Credential Abuse](21-service-principal-and-application-credential-abuse/README.md) | Advanced |
| 22 | [Okta Factor, Session, and Policy Manipulation](22-okta-factor-session-and-policy-manipulation/README.md) | Advanced |
| 23 | [Kerberos Service Ticket and Delegation Abuse](23-kerberos-service-ticket-and-delegation-abuse/README.md) | Advanced |
| 24 | [Directory Replication and Domain Control Abuse](24-directory-replication-and-domain-control-abuse/README.md) | Expert |

## Companion Material

- [Book 2 edition information](../../book/endpoint-and-identity-threats.md)
- [Book 2 technical source notes](../../resources/book-02-source-notes.md)
- [Book 2 figure gallery](../../assets/figures/README.md#book-2--endpoint-and-identity-threats)
- [Repository disclaimer](../../DISCLAIMER.md)

## Validation Status

The examples were statically reviewed against the primary sources listed in the source notes on 17 August 2026. Static review does not establish tenant compatibility, connector availability, local field population, parser behavior, retention, licensing, or production readiness. Those claims require testing against representative records in the operating environment.
