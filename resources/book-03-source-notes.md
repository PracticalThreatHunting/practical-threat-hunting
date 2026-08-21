# Book 3 Technical Source Notes

These source notes support the first edition and were checked against primary documentation through August 20, 2026. Provider documentation changes over time; readers should consult the current linked documentation and the companion repository when validating an implementation.

## Chapter 1

NIST SP 800-201, *Cloud Computing Forensic Reference Architecture*: [official documentation](https://csrc.nist.gov/pubs/sp/800/201/final)

AWS Shared Responsibility Model: [official documentation](https://aws.amazon.com/compliance/shared-responsibility-model/)

Microsoft, *Shared responsibility in the cloud*: [official documentation](https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility)

AWS, *CloudTrail events* and *Logging AWS Lambda API calls using AWS CloudTrail*: [official documentation 1](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html) ; [official documentation 2](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)

GitHub, *OpenID Connect* and *Configuring OIDC in AWS*: [official documentation 1](https://docs.github.com/en/actions/concepts/security/openid-connect) and [official documentation 2](https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)

GitHub, *Audit log events for your organization*: [official documentation](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)

## Chapter 2

AWS, *Understanding CloudTrail events*, *Working with CloudTrail event history*, and *Validating CloudTrail log file integrity*: [official documentation 1](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html) ; [official documentation 2](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html) ; [official documentation 3](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)

Microsoft, *Activity log in Azure Monitor* and *Azure Monitor data sources and collection methods*: [official documentation 1](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log) ; [official documentation 2](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/data-sources)

Microsoft, *Microsoft Entra data retention*: [official documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)

Microsoft, *Learn about auditing solutions in Microsoft Purview*: [official documentation](https://learn.microsoft.com/en-us/purview/audit-solutions-overview)

Google, Admin SDK Reports API, *Admin Activity Report*: [official documentation](https://developers.google.com/workspace/admin/reports/v1/guides/manage-audit-admin)

GitHub, *Reviewing the audit log for your organization*, *Streaming the audit log for your enterprise*, and workflow artifact/log retention: [official documentation 1](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization) ; [official documentation 2](https://docs.github.com/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise) ; [official documentation 3](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization)

## Chapter 3

IETF, *The OAuth 2.0 Authorization Framework (RFC 6749)*: [official documentation](https://datatracker.ietf.org/doc/html/rfc6749)

OpenID Foundation, *OpenID Connect Core 1.0*: [official documentation](https://openid.net/specs/openid-connect-core-1_0.html)

AWS, *Logging IAM and AWS STS API calls with CloudTrail* and *Monitor and control actions taken with assumed roles*: [official documentation 1](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html) ; [official documentation 2](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)

Microsoft, *Application and service principal objects in Microsoft Entra ID* and *Managed identities for Azure resources*: [official documentation 1](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals) ; [official documentation 2](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)

Microsoft, *Workload identity federation*: [official documentation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)

GitHub, *OpenID Connect reference*: [official documentation](https://docs.github.com/en/actions/reference/security/oidc)

## Chapter 4

AWS, *CloudTrail record contents* and *CloudTrail userIdentity element*: [official documentation 1](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) ; [official documentation 2](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)

AWS, *Logging IAM and AWS STS API calls with CloudTrail*: [official documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)

Microsoft, *Service principal sign-in logs* and AADServicePrincipalSignInLogs table reference: [official documentation 1](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-service-principal-sign-ins) ; [official documentation 2](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)

Microsoft, AzureActivity table reference and *Log data ingestion time in Azure Monitor*: [official documentation 1](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity) ; [official documentation 2](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-ingestion-time)

GitHub, *OpenID Connect reference*: [official documentation](https://docs.github.com/en/actions/reference/security/oidc)

## Chapter 5

NIST SP 800-61 Rev. 3 and NIST SP 800-201, incident response and cloud forensic architecture: [official documentation 1](https://csrc.nist.gov/pubs/sp/800/61/r3/final) ; [official documentation 2](https://csrc.nist.gov/pubs/sp/800/201/final)

NIST AI RMF 1.0 and NIST AI 600-1, generative-AI risk considerations: [official documentation 1](https://www.nist.gov/itl/ai-risk-management-framework) ; [official documentation 2](https://doi.org/10.6028/NIST.AI.600-1)

AWS, CloudTrail events, userIdentity, and Amazon S3 API logging with CloudTrail: [official documentation 1](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html) ; [official documentation 2](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) ; [official documentation 3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)

GitHub Actions, OpenID Connect and workflow retention: [official documentation 1](https://docs.github.com/en/actions/reference/security/oidc) ; [official documentation 2](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization)

Microsoft Entra, activity-log schemas and diagnostic settings: [official documentation 1](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-logs) ; [official documentation 2](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-diagnostic-settings-logs-options)

Google Workspace, Admin SDK Reports API activity schemas and retention: [official documentation 1](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list) ; [official documentation 2](https://knowledge.workspace.google.com/admin/reports/data-retention-and-lag-times)

## Chapter 6

AWS, *Logging IAM and AWS STS API calls with AWS CloudTrail*: [official documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)

AWS, *Monitor and control actions taken with assumed roles*: [official documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)

AWS, *CloudTrail \`userIdentity\` element*: [official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)

AWS, *CloudTrail record contents for management, data, and network activity events*: [official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)

AWS, *Create a table for CloudTrail logs in Athena using manual partitioning*: [official documentation](https://docs.aws.amazon.com/athena/latest/ug/create-cloudtrail-table.html)

MITRE ATT&CK, *T1078.004 — Valid Accounts: Cloud Accounts*: [official documentation](https://attack.mitre.org/techniques/T1078/004/)

## Chapter 7

AWS, *Manage AWS accounts with permission sets*: [official documentation](https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html)

AWS, *Logging IAM Identity Center API calls with AWS CloudTrail*: [official documentation](https://docs.aws.amazon.com/singlesignon/latest/userguide/logging-using-cloudtrail.html)

AWS, *CreateAccountAssignment API*: [official documentation](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateAccountAssignment.html)

AWS, *Understand how IAM Access Analyzer findings work*: [official documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html)

AWS, *Policy evaluation logic*: [official documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)

MITRE ATT&CK, *T1098.003 — Account Manipulation: Additional Cloud Roles*: [official documentation](https://attack.mitre.org/techniques/T1098/003/)

## Chapter 8

AWS, *Logging API calls with AWS CloudTrail for AWS Organizations*: [official documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_cloudtrail-integration.html)

AWS, *Service control policies*: [official documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)

AWS, *Resource control policies*: [official documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)

AWS Organizations, *LeaveOrganization API*: [official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_LeaveOrganization.html)

AWS Organizations, *RemoveAccountFromOrganization API*: [official documentation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_RemoveAccountFromOrganization.html)

MITRE ATT&CK, *T1666 — Modify Cloud Resource Hierarchy*: [official documentation](https://attack.mitre.org/techniques/T1666/)

## Chapter 9

AWS CloudTrail, *Working with CloudTrail event history*: [official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)

AWS Organizations, *AWS CloudTrail and AWS Organizations*: [official documentation](https://docs.aws.amazon.com/organizations/latest/userguide/services-that-can-integrate-cloudtrail.html)

AWS CloudTrail, validating log-file integrity: [official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)

AWS CloudTrail, *PutEventSelectors API*: [official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html)

Amazon GuardDuty, data sources and UpdateOrganizationConfiguration API: [official documentation 1](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html) ; [official documentation 2](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_UpdateOrganizationConfiguration.html)

MITRE ATT&CK, Disable or Modify Cloud Log (T1685.002): [official documentation](https://attack.mitre.org/techniques/T1685/002/)

## Chapter 10

Amazon S3, CloudTrail management and object-level data events: [official documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)

AWS CloudTrail, logging and filtering data events: [official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)

AWS KMS, logging API calls with CloudTrail, and Amazon S3 Bucket Key effects on KMS requests: [official documentation 1](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html) ; [official documentation 2](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html)

AWS CloudTrail, event-record contents and cross-account identifiers: [official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)

MITRE ATT&CK, Data from Cloud Storage (T1530): [official documentation](https://attack.mitre.org/techniques/T1530/)

MITRE ATT&CK, Cloud Storage Object Discovery (T1619): [official documentation](https://attack.mitre.org/techniques/T1619/)

## Chapter 11

Amazon EBS, sharing snapshots and owner-side sharing events; EBS direct API CloudTrail limits: [official documentation 1](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html) ; [official documentation 2](https://docs.aws.amazon.com/ebs/latest/userguide/logging-ebs-apis-using-cloudtrail.html)

Amazon EC2, creating an EBS-backed AMI and sharing AMIs with specific AWS accounts: [official documentation 1](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateImage.html) ; [official documentation 2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html)

Amazon RDS, sharing DB snapshots: [official documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html)

Amazon RDS, exporting DB snapshot data to Amazon S3: [official documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ExportSnapshot.html)

MITRE ATT&CK, Create Snapshot (T1578.001): [official documentation](https://attack.mitre.org/techniques/T1578/001/)

MITRE ATT&CK, Transfer Data to Cloud Account (T1537): [official documentation](https://attack.mitre.org/techniques/T1537/)

## Chapter 12

AWS Systems Manager, *Logging AWS Systems Manager API calls with AWS CloudTrail*: [official documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html)

AWS Systems Manager, *Enabling and disabling session logging*: [official documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging.html)

AWS Systems Manager, *Configuring Amazon CloudWatch Logs for Run Command*: [official documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-rc-setting-up-cwlogs.html)

Amazon EC2, *Log connections established over EC2 Instance Connect Endpoint* (OpenTunnel event and request fields): [official documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/log-ec2-instance-connect-endpoint-using-cloudtrail.html)

EC2 Instance Connect, *SendSSHPublicKey API*: [official documentation](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.html)

MITRE ATT&CK, *Cloud Administration Command (T1651)*, *Direct Cloud VM Connections (T1021.008)*, and *SSH (T1021.004)*: [official documentation 1](https://attack.mitre.org/techniques/T1651/) ; [official documentation 2](https://attack.mitre.org/techniques/T1021/008/) ; [official documentation 3](https://attack.mitre.org/techniques/T1021/004/)

## Chapter 13

AWS Lambda, *Logging AWS Lambda API calls using AWS CloudTrail*, UpdateFunctionCode, and FunctionConfiguration: [official documentation 1](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html) ; [official documentation 2](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html) ; [official documentation 3](https://docs.aws.amazon.com/lambda/latest/api/API_FunctionConfiguration.html)

AWS Lambda, *Monitoring Lambda function URLs* (InvokeFunctionUrl CloudTrail data-event coverage): [official documentation](https://docs.aws.amazon.com/lambda/latest/dg/urls-monitoring.html)

AWS Lambda, *Defining Lambda function permissions with an execution role*: [official documentation](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)

AWS Lambda, *Viewing CloudWatch logs for Lambda functions*: [official documentation](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-view.html)

AWS Lambda, *How Lambda processes records from stream and queue-based event sources*: [official documentation](https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html)

MITRE ATT&CK, *Serverless Execution (T1648)*: [official documentation](https://attack.mitre.org/techniques/T1648/)

## Chapter 14

Microsoft Learn, *Run scripts in your VM by using Run Command*: [official documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview)

Microsoft Learn, *Use deployment scripts in Azure Resource Manager templates*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deployment-script-template)

Microsoft Learn, *Runbook execution in Azure Automation*: [official documentation](https://learn.microsoft.com/en-us/azure/automation/automation-runbook-execution)

Microsoft Learn, *Custom Script Extension for Windows*: [official documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows)

Microsoft Learn, *AzureActivity*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity)

MITRE ATT&CK, *Cloud Administration Command (T1651)*: [official documentation](https://attack.mitre.org/techniques/T1651/)

## Chapter 15

Microsoft Learn, *What are managed identity sign-ins in Microsoft Entra?*: [official documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-managed-identity-sign-ins)

Microsoft Learn, *AADManagedIdentitySignInLogs*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs)

Microsoft Learn, *What are the identity logs you can stream to an endpoint?*: [official documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-diagnostic-settings-logs-options)

Microsoft Learn, *Microsoft Entra data retention* and *Configure Microsoft Entra diagnostic settings for activity logs*: [official documentation 1](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention) ; [official documentation 2](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-diagnostic-settings)

MITRE ATT&CK, *Valid Accounts: Cloud Accounts (T1078.004)*: [official documentation](https://attack.mitre.org/techniques/T1078/004/)

## Chapter 16

Microsoft Learn, *AZKVAuditLogs*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azkvauditlogs)

Microsoft Learn, *Azure Key Vault monitoring data reference*: [official documentation](https://learn.microsoft.com/en-us/azure/key-vault/general/monitor-key-vault-reference)

Microsoft Learn, *Azure Key Vault logging*: [official documentation](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)

Microsoft Learn, *Activity log in Azure Monitor*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log)

MITRE ATT&CK, *Credentials from Password Stores: Cloud Secrets Management Stores (T1555.006)*: [official documentation](https://attack.mitre.org/techniques/T1555/006/)

## Chapter 17

Microsoft Learn, *StorageBlobLogs*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs)

Microsoft Learn, *Best practices for monitoring Azure Blob Storage*: [official documentation](https://learn.microsoft.com/en-us/azure/storage/blobs/blob-storage-monitoring-scenarios)

Microsoft Learn, *Grant limited access to data with shared access signatures (SAS)*: [official documentation](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview)

Microsoft Learn, *Monitor Azure Blob Storage*: [official documentation](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage)

MITRE ATT&CK, *Data from Cloud Storage (T1530)*: [official documentation](https://attack.mitre.org/techniques/T1530/)

## Chapter 18

Microsoft Learn, *Restrict managed disks from being imported or exported*: [official documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/disks-restrict-import-export-overview)

Microsoft Learn, *Disks - Grant Access*: [official documentation](https://learn.microsoft.com/en-us/rest/api/compute/disks/grant-access)

Microsoft Learn, *Snapshots - Grant Access*: [official documentation](https://learn.microsoft.com/en-us/rest/api/compute/snapshots/grant-access)

Microsoft Learn, *Create a snapshot of a virtual hard disk*: [official documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk)

Microsoft Learn, *AzureActivity*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity)

MITRE ATT&CK, *Modify Cloud Compute Infrastructure: Create Snapshot (T1578.001)*: [official documentation](https://attack.mitre.org/techniques/T1578/001/)

## Chapter 19

Microsoft Learn, *Monitor Azure Kubernetes Service (AKS)*: [official documentation](https://learn.microsoft.com/en-us/azure/aks/monitor-aks)

Microsoft Learn, *AKSAudit*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksaudit)

Microsoft Learn, *AKSAuditAdmin*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksauditadmin)

Microsoft Learn, *Azure Kubernetes Service monitoring data reference*: [official documentation](https://learn.microsoft.com/en-us/azure/aks/monitor-aks-reference)

MITRE ATT&CK, *Container Administration Command (T1609)*: [official documentation](https://attack.mitre.org/techniques/T1609/)

## Chapter 20

Microsoft Learn, *Activity log in Azure Monitor*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log)

Microsoft Learn, *Virtual network flow logs*: [official documentation](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview)

Microsoft Learn, *Traffic analytics schema and data aggregation*: [official documentation](https://learn.microsoft.com/en-us/azure/network-watcher/traffic-analytics-schema)

Microsoft Learn, *Azure Firewall monitoring data reference*: [official documentation](https://learn.microsoft.com/en-us/azure/firewall/monitor-firewall-reference)

Microsoft Learn, *Flow logging for network security groups*: [official documentation](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview)

MITRE ATT&CK, *Disable or Modify System Firewall: Cloud Firewall (T1686.001)*: [official documentation](https://attack.mitre.org/techniques/T1686/001/)

## Chapter 21

Microsoft Learn, *Access Microsoft Graph activity logs for tenant monitoring*: [official documentation](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)

Microsoft Learn, *Azure Monitor Logs reference — MicrosoftGraphActivityLogs*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs)

Microsoft Learn, *Microsoft Entra data retention*: [official documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)

Microsoft Learn, *Sign-in log activity details*: [official documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details)

MITRE ATT&CK, *Cloud Service Discovery (T1526)*: [official documentation](https://attack.mitre.org/techniques/T1526/)

MITRE ATT&CK, *Data from Information Repositories (T1213)*: [official documentation](https://attack.mitre.org/techniques/T1213/)

## Chapter 22

Microsoft Learn, *What is a device identity?*: [official documentation](https://learn.microsoft.com/en-us/entra/identity/devices/overview)

Microsoft Learn, *Azure Monitor Logs reference — IntuneDevices*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/intunedevices)

Microsoft Learn, *Send log data to Azure Monitor in Microsoft Intune*: [official documentation](https://learn.microsoft.com/en-us/intune/governance/integrate-azure-monitor)

Microsoft Learn, *Use audit logs to track and monitor events in Microsoft Intune*: [official documentation](https://learn.microsoft.com/en-us/intune/governance/monitor-audit-logs)

Microsoft Learn, *How to track linkable identifiers in Microsoft Entra ID*: [official documentation](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-track-linkable-identifiers)

MITRE ATT&CK, *Device Registration (T1098.005)*: [official documentation](https://attack.mitre.org/techniques/T1098/005/)

## Chapter 23

Microsoft Learn, *Mail flow rules (transport rules) in Exchange Online*: [official documentation](https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules)

Microsoft Learn, *Configure mail flow using connectors in Exchange Online*: [official documentation](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/use-connectors-to-configure-mail-flow)

Microsoft Learn, *Azure Monitor Logs reference — OfficeActivity*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity)

Microsoft Learn, *EmailEvents table in the advanced hunting schema*: [official documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)

Microsoft Learn, *Test a mail flow rule in Exchange Online*: [official documentation](https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/test-mail-flow-rules)

MITRE ATT&CK, *Email Forwarding Rule (T1114.003)*: [official documentation](https://attack.mitre.org/techniques/T1114/003/)

## Chapter 24

Microsoft Learn, *Search for eDiscovery activities in the audit log*: [official documentation](https://learn.microsoft.com/en-us/purview/edisc-ref-audit-log)

Microsoft Learn, *Audit log activities*: [official documentation](https://learn.microsoft.com/en-us/purview/audit-log-activities)

Microsoft Learn, *Learn about eDiscovery features and components*: [official documentation](https://learn.microsoft.com/en-us/purview/edisc-features-components)

Microsoft Learn, *Search and export content in eDiscovery*: [official documentation](https://learn.microsoft.com/en-us/purview/edisc-search-export)

Microsoft Learn, *Use a PowerShell script to search the audit log*: [official documentation](https://learn.microsoft.com/en-us/purview/audit-log-search-script)

MITRE ATT&CK, *Data from Information Repositories (T1213)*: [official documentation](https://attack.mitre.org/techniques/T1213/)

## Chapter 25

Google for Developers, *OAuth Token Audit Activity Events*: [official documentation](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token)

Google for Developers, *Reports API activities.list*: [official documentation](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list)

Google for Developers, *Reports API Python quickstart*: [official documentation](https://developers.google.com/workspace/admin/reports/v1/quickstart/python)

Google Workspace Admin Help, *Data retention and lag times*: [official documentation](https://knowledge.workspace.google.com/admin/reports/data-retention-and-lag-times)

Google Workspace Admin Help, *Set up service log exports to BigQuery*: [official documentation](https://knowledge.workspace.google.com/admin/reports/set-up-service-log-exports-to-bigquery)

MITRE ATT&CK, *Application Access Token (T1550.001)*: [official documentation](https://attack.mitre.org/techniques/T1550/001/)

## Chapter 26

Google for Developers, *Drive Audit Activity Events*: [official documentation](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/drive)

Google for Developers, *Reports API activities.list*: [official documentation](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list)

Google for Developers, *Admin Audit Activity Events — Drive settings*: [official documentation](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-docs-settings)

Google for Developers, *Admin Audit Activity Events — Application settings*: [official documentation](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-application-settings)

Google Workspace Admin Help, *Admin log event changes*: [official documentation](https://knowledge.workspace.google.com/admin/reports/admin-log-event-changes)

Google Workspace Admin Help, *Drive log events*: [official documentation](https://knowledge.workspace.google.com/admin/reports/drive-log-events)

## Chapter 27

GitHub, *OpenID Connect reference*: [official documentation](https://docs.github.com/en/actions/reference/security/oidc)

GitHub, *Configuring OpenID Connect in Amazon Web Services*: [official documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)

GitHub, *OpenID Connect with reusable workflows*: [official documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows)

AWS Identity and Access Management, *Logging IAM and AWS STS API calls with AWS CloudTrail*: [official documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)

Microsoft Entra, *Federated identity credentials overview*: [official documentation](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview)

Microsoft Azure Monitor, *AADServicePrincipalSignInLogs table*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)

## Chapter 28

Microsoft Azure Monitor, *SigninLogs table*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

AWS IAM Identity Center, *CloudTrail use cases for IAM Identity Center*: [official documentation](https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-cloudtrail-use-cases.html)

AWS IAM Identity Center, *Sign-in event examples*: [official documentation](https://docs.aws.amazon.com/singlesignon/latest/userguide/sign-in-events-examples.html)

Microsoft, *Office 365 Management Activity API schema*: [official documentation](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema)

Microsoft Purview, *Manage audit log retention policies*: [official documentation](https://learn.microsoft.com/en-us/purview/audit-log-retention-policies)

MITRE ATT&CK, *Valid Accounts: Cloud Accounts (T1078.004)*: [official documentation](https://attack.mitre.org/techniques/T1078/004/)

## Chapter 29

NIST, *SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management*: [official documentation](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

NIST, *SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response*: [official documentation](https://csrc.nist.gov/pubs/sp/800/86/final)

NIST, *SP 800-201 — NIST Cloud Computing Forensic Reference Architecture*: [official documentation](https://csrc.nist.gov/pubs/sp/800/201/final)

AWS CloudTrail, *CloudTrail userIdentity element*: [official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)

Microsoft Entra, *How long does Microsoft Entra store reporting data?*: [official documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)

Google Workspace Admin SDK, *Reports API Activity resource*: [official documentation](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities)

## Chapter 30

MITRE ATT&CK, *Detection of Abused or Compromised Cloud Accounts for Access and Persistence (DET0546)*: [official documentation](https://attack.mitre.org/detectionstrategies/DET0546/)

SigmaHQ, *Sigma rules*: [official documentation](https://sigmahq.io/docs/basics/rules.html)

SigmaHQ, *Sigma correlations*: [official documentation](https://sigmahq.io/docs/meta/correlations.html)

NIST, *SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management*: [official documentation](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

## Chapter 31

Amazon Athena, *Query AWS CloudTrail logs*: [official documentation](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)

Amazon CloudWatch Logs, *CloudWatch Logs Insights operations and functions* (jsonParse, jsonStringify, and isblank) and *Supported logs and discovered fields*: [official documentation 1](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-operations-functions.html) ; [official documentation 2](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData-discoverable-fields.html)

Amazon Security Lake, *Open Cybersecurity Schema Framework in Security Lake*: [official documentation](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html)

Microsoft Azure Monitor, *SigninLogs table*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

Microsoft Graph, *List signIns*: [official documentation](https://learn.microsoft.com/en-us/graph/api/signin-list)

Microsoft Sentinel, *Normalization and the Advanced Security Information Model*: [official documentation](https://learn.microsoft.com/en-us/azure/sentinel/normalization)

## Chapter 32

AWS CloudTrail, *Viewing CloudTrail cost and usage with AWS Cost Explorer*: [official documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-costs.html)

Amazon Athena, *Query AWS CloudTrail logs*: [official documentation](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)

Microsoft Azure Monitor, *Manage data retention in a Log Analytics workspace*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure)

Microsoft Azure Monitor, *Azure Monitor Logs cost calculations and options*: [official documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cost-logs)

Google Workspace, *Data retention and lag times*: [official documentation](https://knowledge.workspace.google.com/admin/reports/data-retention-and-lag-times)

GitHub, *Configuring retention for GitHub Actions artifacts and logs in an organization*: [official documentation](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization)

## Chapter 33

NIST, *SP 800-218 — Secure Software Development Framework Version 1.1*: [official documentation](https://csrc.nist.gov/pubs/sp/800/218/final)

NIST, *SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response*: [official documentation](https://csrc.nist.gov/pubs/sp/800/86/final)

GitHub, *Immutable releases*: [official documentation](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)

GitHub, *About API versioning*: [official documentation](https://docs.github.com/en/rest/about-the-rest-api/api-versions)

MITRE ATT&CK, *Version history*: [official documentation](https://attack.mitre.org/resources/versions/)
