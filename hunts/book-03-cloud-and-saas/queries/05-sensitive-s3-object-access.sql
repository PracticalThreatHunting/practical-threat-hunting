WITH s3_access AS (
    SELECT
        from_iso8601_timestamp(eventtime) AS event_time,
        recipientaccountid,
        useridentity.arn AS actor_arn,
        useridentity.sessioncontext.sessionissuer.arn AS session_issuer_arn,
        useridentity.accesskeyid AS access_key_id,
        sourceipaddress,
        useragent,
        eventname,
        sharedeventid,
        eventid,
        json_extract_scalar(requestparameters, '$.bucketName') AS bucket_name,
        json_extract_scalar(requestparameters, '$.key') AS object_key,
        errorcode
    FROM <CLOUDTRAIL_TABLE>
    WHERE eventsource = 's3.amazonaws.com'
      AND eventcategory = 'Data'
      AND <PARTITION_PREDICATE>
      AND eventname IN
          ('ListObjects','ListObjectsV2','ListObjectVersions',
           'GetObject','GetObjectAttributes','SelectObjectContent')
      AND from_iso8601_timestamp(eventtime) >= from_iso8601_timestamp('<START_ISO8601>')
      AND from_iso8601_timestamp(eventtime) < from_iso8601_timestamp('<END_ISO8601>')
      AND json_extract_scalar(requestparameters, '$.bucketName')
          = '<SENSITIVE_BUCKET>'
      AND recipientaccountid = '<REQUESTER_OR_BUCKET_OWNER_ACCOUNT_ID>'
)
SELECT
    date_trunc('hour', event_time) AS hour_utc,
    recipientaccountid,
    actor_arn,
    session_issuer_arn,
    access_key_id,
    sourceipaddress,
    useragent,
    count(DISTINCT coalesce(sharedeventid, eventid)) AS request_count,
    count(DISTINCT object_key) AS distinct_object_keys,
    count(DISTINCT CASE WHEN errorcode IS NULL
                        THEN coalesce(sharedeventid, eventid) END) AS requests_without_error,
    min(event_time) AS first_event,
    max(event_time) AS last_event
FROM s3_access
GROUP BY 1,2,3,4,5,6,7
ORDER BY request_count DESC;
