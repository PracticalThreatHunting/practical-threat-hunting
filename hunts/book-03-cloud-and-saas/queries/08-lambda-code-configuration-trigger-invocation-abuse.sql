WITH hunt_window AS (
    SELECT
        from_iso8601_timestamp('<START_ISO8601>') AS start_time,
        from_iso8601_timestamp('<END_ISO8601>')   AS end_time
)
SELECT
    eventtime,
    recipientaccountid,
    awsregion,
    useridentity.arn         AS actor_arn,
    useridentity.accesskeyid AS access_key_id,
    eventsource,
    eventname,
    sourceipaddress,
    useragent,
    coalesce(json_extract_scalar(requestparameters, '$.functionName'),
             json_extract_scalar(responseelements, '$.functionArn')) AS function_identifier,
    json_extract_scalar(requestparameters, '$.qualifier') AS qualifier,
    json_extract_scalar(requestparameters, '$.name') AS alias_name,
    json_extract_scalar(requestparameters, '$.functionVersion') AS function_version,
    json_extract_scalar(requestparameters, '$.role') AS execution_role_arn,
    json_extract_scalar(requestparameters, '$.eventSourceArn') AS event_source_arn,
    json_extract_scalar(requestparameters, '$.codeSigningConfigArn') AS code_signing_config_arn,
    json_extract_scalar(requestparameters, '$.authType') AS function_url_auth_type,
    json_extract_scalar(responseelements, '$.uUID') AS event_source_mapping_id,
    json_extract_scalar(responseelements, '$.codeSha256') AS code_sha256,
    json_extract_scalar(responseelements, '$.configSha256') AS config_sha256,
    json_extract_scalar(responseelements, '$.version') AS published_version,
    json_extract_scalar(responseelements, '$.revisionId') AS revision_id,
    json_extract_scalar(responseelements, '$.lastUpdateStatus') AS returned_last_update_status,
    errorcode,
    requestid,
    eventid
FROM <CLOUDTRAIL_TABLE>
CROSS JOIN hunt_window
WHERE from_iso8601_timestamp(eventtime) >= hunt_window.start_time
  AND from_iso8601_timestamp(eventtime) < hunt_window.end_time
  AND <PARTITION_PREDICATE>
  AND eventcategory = 'Management'
  AND eventsource = 'lambda.amazonaws.com'
  AND regexp_replace(eventname, '[0-9].*$', '') IN
      ('CreateFunction','DeleteFunction','UpdateFunctionCode','UpdateFunctionConfiguration',
       'PublishVersion','CreateAlias','UpdateAlias','DeleteAlias',
       'AddPermission','RemovePermission',
       'CreateFunctionUrlConfig','UpdateFunctionUrlConfig','DeleteFunctionUrlConfig',
       'CreateEventSourceMapping','UpdateEventSourceMapping','DeleteEventSourceMapping',
       'PublishLayerVersion','DeleteLayerVersion','AddLayerVersionPermission',
       'RemoveLayerVersionPermission','PutFunctionConcurrency','DeleteFunctionConcurrency',
       'PutProvisionedConcurrencyConfig','DeleteProvisionedConcurrencyConfig',
       'PutFunctionEventInvokeConfig','UpdateFunctionEventInvokeConfig',
       'DeleteFunctionEventInvokeConfig','PutFunctionCodeSigningConfig',
       'DeleteFunctionCodeSigningConfig','CreateCodeSigningConfig',
       'UpdateCodeSigningConfig','DeleteCodeSigningConfig',
       'PutRuntimeManagementConfig')
ORDER BY eventtime;
