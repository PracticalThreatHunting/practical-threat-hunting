# Book 2 Technical Source Notes

Primary references for *Practical Threat Hunting: Endpoint and Identity Threats*. The book's external links and repository link were reviewed on **17 August 2026**.

These references establish documented tables, fields, event concepts, operators, standards, and technique mappings. They do not establish that a reader's tenant collects or populates the same data. Inspect representative records and the live connector schema before adapting any query.

## Microsoft Defender XDR

- [Advanced hunting schema tables](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Advanced hunting query best practices](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices)
- [Custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)
- [`DeviceProcessEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [`DeviceFileEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [`DeviceRegistryEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table)
- [`DeviceNetworkEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [`DeviceLogonEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
- [`DeviceImageLoadEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table)
- [`DeviceFileCertificateInfo`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefilecertificateinfo-table)
- [`DeviceEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)
- [`IdentityDirectoryEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table)
- [`IdentityLogonEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table)
- [`IdentityQueryEvents`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityqueryevents-table)
- [`IdentityInfo`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table)

## Microsoft Entra ID, Sentinel, and Azure Monitor

- [Azure Monitor table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables-category)
- [`SigninLogs`](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [`AuditLogs`](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- [`AADServicePrincipalSignInLogs`](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)
- [`WindowsEvent`](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/windowsevent)
- [Microsoft Entra activity-log schemas](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas)
- [Microsoft Entra audit activity catalog](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- [Microsoft Entra sign-in logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)
- [Service-principal sign-ins](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-service-principal-sign-ins)
- [Windows Security events for Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference)

## Windows, Sysmon, PowerShell, and Active Directory

- [Sysmon overview](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Configure Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)
- [PowerShell logging on Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [PowerShell security features](https://learn.microsoft.com/en-us/powershell/scripting/security/security-features)
- [PowerShell Group Policy settings](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings)
- [Windows event 4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662)
- [Windows event 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- [Windows event 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Windows event 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [DS-Replication-Get-Changes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1878718d-ca72-472e-a612-ebbf22514236)
- [DS-Replication-Get-Changes-All](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c61ae7fd-c50f-4813-a8d2-ef81d4b48499)

## Okta

- [Okta System Log API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/systemlog)
- [Okta System Log query guidance](https://developer.okta.com/docs/reference/system-log-query/)
- [Okta Event Types catalog](https://developer.okta.com/docs/reference/api/event-types/)

## Query Languages

- [Kusto Query Language overview](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric)
- [Splunk Search Reference](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0)

## Frameworks and AI Risk

- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Microsoft Security Copilot promptbooks](https://learn.microsoft.com/en-us/copilot/security/using-promptbooks)
- [Prompting Microsoft Security Copilot](https://learn.microsoft.com/en-us/copilot/security/prompting-security-copilot)

## Validation Rules

Before operational use:

1. Confirm that the table or event source exists in the target environment.
2. Inspect recent raw samples before selecting fields.
3. Verify field type, null behavior, nested structure, and time semantics.
4. Test known benign and controlled-positive cases.
5. Record query version, product version, and documentation date.
6. Revalidate after connector, licensing, parser, schema, or product changes.

Report broken links, outdated fields, or technical corrections through the repository's GitHub Issues.
