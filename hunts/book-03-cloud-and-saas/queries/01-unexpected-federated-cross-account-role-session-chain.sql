WITH issued_candidates AS (
  SELECT from_iso8601_timestamp(eventtime) AS issued_at,
         useridentity.arn AS caller_arn,
         useridentity.type AS caller_type,
         awsregion AS issuance_aws_region,
         eventname AS sts_event,
         json_extract_scalar(requestparameters, '$.roleArn') AS target_role_arn,
         json_extract_scalar(requestparameters, '$.roleSessionName') AS role_session_name,
         json_extract_scalar(requestparameters, '$.sourceIdentity') AS source_identity,
         json_extract_scalar(responseelements, '$.credentials.accessKeyId') AS temp_access_key,
         json_extract_scalar(responseelements, '$.assumedRoleUser.arn') AS issued_session_arn,
         json_extract_scalar(additionaleventdata, '$.RequestDetails.endpointType') AS endpoint_type,
         json_extract_scalar(additionaleventdata, '$.RequestDetails.awsServingRegion') AS aws_serving_region,
         recipientaccountid AS issuance_recipient_account_id,
         sharedeventid AS shared_event_id,
         eventid AS issuance_event_id
  FROM <CLOUDTRAIL_TABLE>
  WHERE eventsource = 'sts.amazonaws.com'
    AND eventcategory = 'Management'
    AND <ISSUANCE_PARTITION_PREDICATE>
    AND eventname IN ('AssumeRole','AssumeRoleWithSAML','AssumeRoleWithWebIdentity')
    AND errorcode IS NULL
    AND json_extract_scalar(responseelements, '$.credentials.accessKeyId') IS NOT NULL
    AND from_iso8601_timestamp(eventtime) >= from_iso8601_timestamp('<START_ISO8601>')
    AND from_iso8601_timestamp(eventtime) < from_iso8601_timestamp('<END_ISO8601>') ),
issued AS (
  SELECT issued_at, caller_arn, caller_type, issuance_aws_region, sts_event,
         target_role_arn, role_session_name, source_identity, temp_access_key,
         issued_session_arn, endpoint_type, aws_serving_region, issuance_recipient_account_id,
         shared_event_id, issuance_event_id
  FROM (
    SELECT c.*,
           row_number() OVER (
             PARTITION BY coalesce(c.shared_event_id, c.issuance_event_id)
             ORDER BY CASE WHEN c.caller_arn IS NOT NULL THEN 0 ELSE 1 END,
                      c.issuance_event_id
           ) AS perspective_rank
    FROM issued_candidates c
  ) ranked
  WHERE perspective_rank = 1
)
SELECT i.issued_at, i.caller_arn, i.caller_type, i.issuance_aws_region,
       i.endpoint_type, i.aws_serving_region, i.sts_event, i.target_role_arn,
       i.role_session_name, i.source_identity, i.issued_session_arn,
       i.issuance_recipient_account_id,
       i.issuance_event_id, i.shared_event_id AS issuance_shared_event_id,
       a.eventtime, a.awsregion, a.eventcategory, a.eventtype,
       a.eventsource, a.eventname,
       a.recipientaccountid, a.useridentity.arn AS session_arn,
       a.sourceipaddress, a.errorcode, a.errormessage, a.requestid,
       a.eventid, a.sharedeventid
FROM issued i
JOIN <CLOUDTRAIL_TABLE> a ON a.useridentity.accesskeyid = i.temp_access_key
WHERE <ACTION_PARTITION_PREDICATE>
  AND from_iso8601_timestamp(a.eventtime) >= i.issued_at
  AND from_iso8601_timestamp(a.eventtime) < from_iso8601_timestamp('<END_ISO8601>')
ORDER BY i.issued_at, a.eventtime;
