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
    json_extract_scalar(requestparameters, '$.documentName') AS document_name,
    json_extract_scalar(requestparameters, '$.documentVersion') AS document_version,
    json_extract(requestparameters, '$.instanceIds') AS send_command_instance_ids,
    json_extract(requestparameters, '$.targets') AS send_command_targets,
    json_extract_scalar(requestparameters, '$.target') AS session_target,
    json_extract_scalar(requestparameters, '$.sessionId') AS requested_session_id,
    json_extract_scalar(requestparameters, '$.instanceId') AS ssh_instance_id,
    json_extract_scalar(requestparameters, '$.availabilityZone') AS ssh_availability_zone,
    json_extract_scalar(requestparameters, '$.instanceOSUser') AS ssh_instance_os_user,
    json_extract_scalar(requestparameters, '$.instanceConnectEndpointId') AS tunnel_endpoint_id,
    json_extract_scalar(requestparameters, '$.privateIpAddress') AS tunnel_private_ip,
    json_extract_scalar(requestparameters, '$.remotePort') AS tunnel_remote_port,
    json_extract_scalar(requestparameters, '$.maxTunnelDuration') AS tunnel_max_duration_seconds,
    json_extract_scalar(responseelements, '$.command.commandId') AS command_id,
    json_extract_scalar(responseelements, '$.sessionId') AS session_id,
    errorcode,
    requestid,
    eventid
FROM <CLOUDTRAIL_TABLE>
CROSS JOIN hunt_window
WHERE from_iso8601_timestamp(eventtime) >= hunt_window.start_time
  AND from_iso8601_timestamp(eventtime) < hunt_window.end_time
  AND <PARTITION_PREDICATE>
  AND eventcategory = 'Management'
  AND (
        (eventsource = 'ssm.amazonaws.com'
         AND eventname IN ('SendCommand', 'StartSession', 'ResumeSession', 'TerminateSession'))
     OR (eventsource = 'ec2-instance-connect.amazonaws.com'
         AND eventname IN ('SendSSHPublicKey', 'OpenTunnel'))
      )
ORDER BY eventtime;
