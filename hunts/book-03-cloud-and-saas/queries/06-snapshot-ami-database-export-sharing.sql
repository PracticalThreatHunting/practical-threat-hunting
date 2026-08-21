SELECT
    from_iso8601_timestamp(eventtime) AS event_time,
    recipientaccountid,
    awsregion,
    eventsource,
    eventname,
    useridentity.arn AS actor_arn,
    useridentity.sessioncontext.sessionissuer.arn AS session_issuer_arn,
    useridentity.accesskeyid AS access_key_id,
    sourceipaddress,
    useragent,
    errorcode,
    eventid,
    requestparameters,
    responseelements
FROM <CLOUDTRAIL_TABLE>
WHERE <PARTITION_PREDICATE>
  AND from_iso8601_timestamp(eventtime) >= from_iso8601_timestamp('<START_ISO8601>')
  AND from_iso8601_timestamp(eventtime) < from_iso8601_timestamp('<END_ISO8601>')
  AND eventcategory = 'Management'
  AND (
       (eventsource = 'ec2.amazonaws.com' AND eventname IN
          ('CreateSnapshot','CopySnapshot','ModifySnapshotAttribute','CreateImage',
           'SharedSnapshotCopyInitiated','SharedSnapshotVolumeCreated',
           'RegisterImage','CopyImage','ModifyImageAttribute',
           'CreateVolume','RunInstances'))
    OR (eventsource = 'rds.amazonaws.com' AND eventname IN
          ('CreateDBSnapshot','CopyDBSnapshot','ModifyDBSnapshotAttribute',
           'RestoreDBInstanceFromDBSnapshot','CreateDBClusterSnapshot',
           'CopyDBClusterSnapshot','ModifyDBClusterSnapshotAttribute',
           'RestoreDBClusterFromSnapshot','StartExportTask','CancelExportTask'))
  )
ORDER BY event_time;
