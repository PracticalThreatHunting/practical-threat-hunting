WITH exchanges AS (
    SELECT exchange_id, exchange_event_time AS exchange_time,
           exchange_ingest_time, 'aws' AS cloud, cloud_identity_id,
           subject AS upstream_subject, audience AS upstream_audience,
           NULL AS target_resource_identity, session_or_signin_id,
           temporary_access_key_id, federated_credential_id,
           exchange_result
    FROM <AWS_WEB_IDENTITY_EXCHANGES>
    WHERE exchange_event_time >= (<START_UTC>)
      AND exchange_event_time < (<END_UTC>)
    UNION ALL
    SELECT exchange_id, created_date_time AS exchange_time,
           time_generated AS exchange_ingest_time,
           'azure' AS cloud, service_principal_id,
           NULL AS upstream_subject, NULL AS upstream_audience,
           resource_identity AS target_resource_identity, signin_id,
           NULL AS temporary_access_key_id, federated_credential_id,
           exchange_result
    FROM <ENTRA_FEDERATED_SERVICE_PRINCIPAL_SIGNINS>
    WHERE created_date_time >= (<START_UTC>)
      AND created_date_time < (<END_UTC>)
), mapped AS (
    SELECT e.*, t.repository_id, t.expected_subject, t.expected_audience,
           t.workflow_ref, t.trust_match_result, t.matcher_version,
           t.allowed_scope_id, t.effective_from, t.effective_to
    FROM exchanges e
    LEFT JOIN <VERSIONED_TRUST_MATCH_RESULTS> t
      ON t.exchange_id = e.exchange_id
     AND e.exchange_time >= t.effective_from
     AND e.exchange_time < t.effective_to
)
SELECT m.exchange_time, m.exchange_ingest_time, m.cloud,
       m.cloud_identity_id, m.repository_id,
       m.upstream_audience, m.expected_audience, m.target_resource_identity,
       m.exchange_result, m.trust_match_result, m.matcher_version,
       g.run_id, g.commit_sha, g.ref, g.environment, g.job_workflow_ref,
       a.action_time, a.operation, a.resource_id, a.result,
       a.edge_basis AS action_edge_basis,
       a.edge_corroborated AS action_edge_corroborated,
       a.scope_allowed,
       CASE WHEN m.exchange_result IS NULL THEN 'exchange_result_unknown'
            WHEN m.exchange_result <> 'success' THEN 'exchange_failed_or_denied'
            WHEN m.trust_match_result IS NULL THEN 'trust_unresolved'
            WHEN m.trust_match_result <> 'matched' THEN 'trust_not_matched'
            WHEN a.action_time IS NULL THEN 'no_correlated_action'
            WHEN m.cloud = 'azure'
             AND (a.edge_corroborated IS NULL OR a.edge_corroborated IS FALSE)
              THEN 'candidate_action_edge'
            WHEN a.scope_allowed IS FALSE THEN 'scope_mismatch'
            WHEN a.scope_allowed IS NULL THEN 'scope_evaluation_unresolved'
            ELSE 'review' END AS reason
FROM mapped m
LEFT JOIN <GITHUB_RUNS> g
  ON g.repository_id = m.repository_id
 AND g.run_time >= <RUN_WINDOW_START>(m.exchange_time)
 AND g.run_time < (<RUN_WINDOW_END>(m.exchange_time))
LEFT JOIN <NORMALIZED_CLOUD_ACTIONS> a
  ON a.cloud = m.cloud
 AND m.exchange_result = 'success'
 AND ((m.cloud = 'aws'
       AND a.temporary_access_key_id = m.temporary_access_key_id)
      OR (m.cloud = 'azure'
          AND a.cloud_identity_id = m.cloud_identity_id))
 AND a.action_time >= m.exchange_time
 AND a.action_time < (<ACTION_WINDOW_END>(m.exchange_time));
