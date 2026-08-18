# Threat Hunts

The repository contains book-specific implementation resources for the **Practical Threat Hunting** series. The books teach durable methodology; these directories carry query implementations and technical material that can change with vendor schemas.

## Book 1 — Modern Techniques for the AI-Augmented SOC

The existing numbered directories at the root of `hunts/` remain the stable companion paths for Book 1's 25 hunts.

- **Hunt 01:** [Suspicious PowerShell Execution](01-suspicious-powershell-execution/README.md) — Foundational
- **Hunt 02:** [Living-off-the-Land Execution](02-living-off-the-land-execution/README.md) — Foundational–Intermediate
- **Hunt 03:** [Credential Access and LSASS Targeting](03-credential-access-and-lsass-targeting/README.md) — Intermediate
- **Hunt 04:** [Persistence Through Services, Scheduled Tasks, and Registry Run Keys](04-persistence-through-services-scheduled-tasks-and-registry-run-keys/README.md) — Intermediate
- **Hunt 05:** [Defense Impairment and Security-Control Tampering](05-defense-impairment-and-security-control-tampering/README.md) — Intermediate
- **Hunt 06:** [Password Spraying and Distributed Authentication Attacks](06-password-spraying-and-distributed-authentication-attacks/README.md) — Foundational–Intermediate
- **Hunt 07:** [MFA Abuse and Session Hijacking](07-mfa-abuse-and-session-hijacking/README.md) — Intermediate–Advanced
- **Hunt 08:** [Suspicious Privileged Role Activity](08-suspicious-privileged-role-activity/README.md) — Intermediate
- **Hunt 09:** [Malicious OAuth Consent and Service Principal Abuse](09-malicious-oauth-consent-and-service-principal-abuse/README.md) — Advanced
- **Hunt 10:** [Malicious Mailbox Rules and Email Persistence](10-malicious-mailbox-rules-and-email-persistence/README.md) — Intermediate
- **Hunt 11:** [SharePoint and OneDrive Collection and Exfiltration](11-sharepoint-and-onedrive-collection-and-exfiltration/README.md) — Intermediate–Advanced
- **Hunt 12:** [Compromised Cloud Credentials](12-compromised-cloud-credentials/README.md) — Intermediate
- **Hunt 13:** [Cloud IAM Persistence and Privilege Escalation](13-cloud-iam-persistence-and-privilege-escalation/README.md) — Intermediate–Advanced
- **Hunt 14:** [Cloud Logging and Defense Impairment](14-cloud-logging-and-defense-impairment/README.md) — Intermediate
- **Hunt 15:** [Cloud Data Collection and Exfiltration](15-cloud-data-collection-and-exfiltration/README.md) — Advanced
- **Hunt 16:** [Workload and Instance Metadata Credential Abuse](16-workload-and-instance-metadata-credential-abuse/README.md) — Advanced
- **Hunt 17:** [Endpoint Compromise to Cloud Access](17-endpoint-compromise-to-cloud-access/README.md) — Advanced
- **Hunt 18:** [Identity Compromise to Microsoft 365 Collection](18-identity-compromise-to-microsoft-365-collection/README.md) — Advanced
- **Hunt 19:** [Command-and-Control and Beaconing](19-command-and-control-and-beaconing/README.md) — Advanced
- **Hunt 20:** [Threat-Intelligence-Driven Campaign Hunt](20-threat-intelligence-driven-campaign-hunt/README.md) — Advanced capstone
- **Hunt 21:** [Shadow AI and Unsanctioned GenAI Usage](21-shadow-ai-and-unsanctioned-genai-usage/README.md) — Intermediate
- **Hunt 22:** [Sensitive Data Exposure to AI Services](22-sensitive-data-exposure-to-ai-services/README.md) — Advanced
- **Hunt 23:** [AI API Key and Service Identity Compromise](23-ai-api-key-and-service-identity-compromise/README.md) — Advanced
- **Hunt 24:** [Prompt Injection and Agent Tool Abuse](24-prompt-injection-and-agent-tool-abuse/README.md) — Advanced
- **Hunt 25:** [AI Agent Persistence, RAG Manipulation, and Data Poisoning](25-ai-agent-persistence-rag-manipulation-and-data-poisoning/README.md) — Advanced capstone

## Book 2 — Endpoint and Identity Threats

Book 2 has a separate namespace so overlapping hunt numbers cannot be confused with Book 1.

- [Browse all 24 Book 2 hunts](book-02-endpoint-and-identity/README.md)
- [Book 2 technical source notes](../resources/book-02-source-notes.md)
- [Book 2 figure gallery](../assets/figures/README.md#book-2--endpoint-and-identity-threats)

## Query Guidance

Queries are reference implementations. Validate them in a controlled or read-only hunting workflow before production use. Platform schemas, operation names, field semantics, licensing, and local data quality can change.

## Template

Use [`00-hunt-template/README.md`](00-hunt-template/README.md) when adding or revising a hunt.
