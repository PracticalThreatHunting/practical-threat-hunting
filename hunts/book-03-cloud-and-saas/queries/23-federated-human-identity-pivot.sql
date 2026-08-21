SELECT
    e.event_time AS entra_time,
    e.user_id AS entra_user_id,
    e.signin_id,
    e.session_id AS entra_session_id,
    e.ip_address AS entra_ip,
    x.identity_store_user_id,
    COALESCE(a.provider_asserted_identity_store_user_id,
             a.derived_identity_store_user_id) AS aws_identity_store_user_id,
    a.event_time AS aws_time,
    a.account_id,
    a.role_or_permission_set,
    a.access_key_id,
    m.event_time AS m365_time,
    m.workload,
    m.operation,
    m.object_id,
    CASE WHEN x.entra_user_id IS NULL THEN TRUE ELSE FALSE END
      AS identity_mapping_unresolved,
    CASE
      WHEN x.entra_user_id IS NULL THEN 'identity_mapping_unresolved'
      WHEN a.provider_asserted_identity_store_user_id IS NOT NULL
        THEN 'provider_asserted_identity_store_user_id'
      WHEN a.derived_identity_store_user_id IS NOT NULL
        THEN 'derived_identity_center_role_session_access_key_chain'
      ELSE 'no_aws_identity_edge'
    END AS entra_to_aws_join_basis,
    CASE
      WHEN x.entra_user_id IS NULL THEN 'identity_mapping_unresolved'
      WHEN m.validated_immutable_user_key IS NOT NULL
        THEN 'validated_immutable_m365_identity'
      WHEN m.normalized_user_id IS NOT NULL THEN 'mutable_m365_identity'
      ELSE 'no_m365_identity_edge'
    END AS entra_to_m365_join_basis
FROM <ENTRA_HUMAN_SIGNINS> e
LEFT JOIN <EFFECTIVE_DATED_IDENTITY_CROSSWALK> x
  ON x.entra_user_id = e.user_id
 AND e.event_time >= x.effective_from
 AND e.event_time < x.effective_to
LEFT JOIN <AWS_FEDERATED_HUMAN_ACTIVITY> a
  ON (a.provider_asserted_identity_store_user_id = x.identity_store_user_id
      OR a.derived_identity_store_user_id = x.identity_store_user_id)
 AND a.event_time >= <AWS_WINDOW_START>(e.event_time)
 AND a.event_time < (<AWS_WINDOW_END>(e.event_time))
LEFT JOIN <M365_AUDIT_ACTIVITY> m
  ON (m.validated_immutable_user_key = x.m365_immutable_user_key
      OR m.normalized_user_id = x.m365_user_id_at_event)
 AND m.event_time >= <M365_WINDOW_START>(e.event_time)
 AND m.event_time < (<M365_WINDOW_END>(e.event_time))
WHERE e.event_time >= (<START_UTC>) AND e.event_time < (<END_UTC>);
