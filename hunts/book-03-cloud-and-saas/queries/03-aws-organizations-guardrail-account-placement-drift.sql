SELECT eventtime, awsregion, eventcategory, eventtype, eventsource, eventname,
       useridentity.arn AS actor_arn, recipientaccountid,
       sourceipaddress, useragent,
       json_extract_scalar(requestparameters, '$.accountId') AS account_id,
       json_extract_scalar(requestparameters, '$.sourceParentId') AS source_parent_id,
       json_extract_scalar(requestparameters, '$.destinationParentId') AS destination_parent_id,
       json_extract_scalar(requestparameters, '$.policyId') AS policy_id,
       json_extract_scalar(requestparameters, '$.rootId') AS root_id,
       json_extract_scalar(requestparameters, '$.policyType') AS policy_type,
       coalesce(json_extract_scalar(requestparameters, '$.targetId'),
                json_extract_scalar(requestparameters, '$.servicePrincipal')) AS target_or_service,
       errorcode, errormessage, requestid, eventid,
       requestparameters, responseelements
FROM <CLOUDTRAIL_TABLE>
WHERE eventsource = 'organizations.amazonaws.com'
  AND eventcategory = 'Management'
  AND <PARTITION_PREDICATE>
  AND awsregion = 'us-east-1'
  AND eventname IN ('MoveAccount','RemoveAccountFromOrganization','LeaveOrganization',
                    'AttachPolicy','DetachPolicy','UpdatePolicy',
                    'EnablePolicyType','DisablePolicyType','RegisterDelegatedAdministrator',
                    'DeregisterDelegatedAdministrator','EnableAWSServiceAccess','DisableAWSServiceAccess')
  AND from_iso8601_timestamp(eventtime) >= from_iso8601_timestamp('<START_ISO8601>')
  AND from_iso8601_timestamp(eventtime) < from_iso8601_timestamp('<END_ISO8601>')
ORDER BY eventtime;
