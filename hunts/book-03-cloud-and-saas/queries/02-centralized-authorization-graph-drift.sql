SELECT eventtime, awsregion, eventcategory, eventtype, eventsource, eventname,
       useridentity.arn AS actor_arn,
       recipientaccountid,
       sourceipaddress, useragent,
       coalesce(json_extract_scalar(requestparameters, '$.principalId'),
                json_extract_scalar(requestparameters, '$.memberId.userId'),
                json_extract_scalar(requestparameters, '$.roleName')) AS changed_principal,
       json_extract_scalar(requestparameters, '$.membershipId') AS membership_id,
       json_extract_scalar(requestparameters, '$.permissionSetArn') AS permission_set_arn,
       coalesce(json_extract_scalar(requestparameters, '$.targetId'),
                json_extract_scalar(requestparameters, '$.policyArn'),
                json_extract_scalar(requestparameters, '$.groupId'),
                json_extract_scalar(requestparameters, '$.id'),
                json_extract_scalar(requestparameters, '$.bucketName'),
                json_extract_scalar(requestparameters, '$.keyId')) AS target_or_policy,
       errorcode, errormessage, requestid, eventid,
       requestparameters, responseelements
FROM <CLOUDTRAIL_TABLE>
WHERE <PARTITION_PREDICATE>
  AND eventcategory = 'Management'
  AND from_iso8601_timestamp(eventtime) >= from_iso8601_timestamp('<START_ISO8601>')
  AND from_iso8601_timestamp(eventtime) < from_iso8601_timestamp('<END_ISO8601>')
  AND ((eventsource = 'sso.amazonaws.com' AND eventname IN
        ('CreateAccountAssignment','DeleteAccountAssignment','PutInlinePolicyToPermissionSet',
         'DeleteInlinePolicyFromPermissionSet','AttachManagedPolicyToPermissionSet',
         'DetachManagedPolicyFromPermissionSet','AttachCustomerManagedPolicyReferenceToPermissionSet',
         'DetachCustomerManagedPolicyReferenceFromPermissionSet','PutPermissionsBoundaryToPermissionSet',
         'DeletePermissionsBoundaryFromPermissionSet','UpdatePermissionSet','ProvisionPermissionSet'))
    OR (eventsource = 'identitystore.amazonaws.com' AND eventname IN
        ('CreateGroupMembership','DeleteGroupMembership'))
    OR (eventsource = 'sso-directory.amazonaws.com' AND eventname IN
        ('AddMemberToGroup','RemoveMemberFromGroup'))
    OR (eventsource = 'identitystore-scim.amazonaws.com' AND eventname = 'PatchGroup')
    OR (eventsource = 'iam.amazonaws.com' AND eventname IN
        ('UpdateAssumeRolePolicy','PutRolePolicy','DeleteRolePolicy','AttachRolePolicy',
         'DetachRolePolicy','PutRolePermissionsBoundary','DeleteRolePermissionsBoundary',
         'CreatePolicyVersion','SetDefaultPolicyVersion'))
    OR (eventsource = 's3.amazonaws.com' AND eventname = 'PutBucketPolicy')
    OR (eventsource = 'kms.amazonaws.com' AND eventname = 'PutKeyPolicy'))
ORDER BY eventtime;
