SELECT
    from_iso8601_timestamp(eventtime) AS event_time,
    recipientaccountid,
    awsregion,
    eventcategory,
    eventtype,
    eventsource,
    eventname,
    useridentity.arn AS actor_arn,
    useridentity.sessioncontext.sessionissuer.arn AS session_issuer_arn,
    useridentity.accesskeyid AS access_key_id,
    sourceipaddress,
    useragent,
    errorcode,
    errormessage,
    requestid,
    eventid,
    requestparameters,
    responseelements
FROM <CLOUDTRAIL_TABLE>
WHERE <PARTITION_PREDICATE>
  AND eventcategory = 'Management'
  AND from_iso8601_timestamp(eventtime) >= from_iso8601_timestamp('<START_ISO8601>')
  AND from_iso8601_timestamp(eventtime) < from_iso8601_timestamp('<END_ISO8601>')
  AND (
       (eventsource = 'cloudtrail.amazonaws.com' AND eventname IN
          ('StopLogging','StartLogging','DeleteTrail','UpdateTrail','PutEventSelectors','PutInsightSelectors'))
    OR (eventsource = 'organizations.amazonaws.com'
        AND eventname = 'DisableAWSServiceAccess'
        AND json_extract_scalar(requestparameters, '$.servicePrincipal') = 'cloudtrail.amazonaws.com')
    OR (eventsource = 'config.amazonaws.com' AND eventname IN
          ('StopConfigurationRecorder','DeleteConfigurationRecorder','PutConfigurationRecorder',
           'DeleteDeliveryChannel','PutDeliveryChannel','PutRetentionConfiguration',
           'DeleteRetentionConfiguration'))
    OR (eventsource = 'logs.amazonaws.com' AND eventname IN
          ('PutSubscriptionFilter','DeleteSubscriptionFilter','PutDestination','PutDestinationPolicy',
           'DeleteDestination','PutRetentionPolicy','DeleteLogGroup'))
    OR (eventsource = 's3.amazonaws.com' AND eventname IN
          ('PutBucketPolicy','DeleteBucketPolicy','PutBucketLifecycle','DeleteBucketLifecycle',
           'PutBucketEncryption','DeleteBucketEncryption','DeleteBucket'))
    OR (eventsource = 'kms.amazonaws.com' AND eventname IN
          ('DisableKey','ScheduleKeyDeletion','PutKeyPolicy'))
    OR (eventsource = 'guardduty.amazonaws.com' AND eventname IN
          ('UpdateDetector','DeleteDetector','UpdateOrganizationConfiguration','StopMonitoringMembers'))
    OR (eventsource = 'securityhub.amazonaws.com' AND eventname = 'DisableSecurityHub')
    OR (eventsource = 'ec2.amazonaws.com' AND eventname = 'DeleteFlowLogs')
  )
ORDER BY event_time;
