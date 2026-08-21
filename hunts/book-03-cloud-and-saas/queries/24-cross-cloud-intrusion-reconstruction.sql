WITH e AS (
    SELECT *
    FROM <CANONICAL_CROSS_CLOUD_EVENTS>
    WHERE event_time_utc >= (<START_UTC>) AND event_time_utc < (<END_UTC>)
), exact_edges AS (
    SELECT
        l.normalized_event_id AS left_event_id,
        r.normalized_event_id AS right_event_id,
        'exact_identifier' AS edge_basis,
        li.identifier_type AS matched_key_type,
        li.identifier_namespace AS matched_key_namespace,
        li.identifier_value AS matched_key_value,
        l.provider_scope AS left_provider_scope,
        r.provider_scope AS right_provider_scope,
        l.event_time_utc AS left_time,
        r.event_time_utc AS right_time,
        l.coverage_state AS left_coverage_state,
        r.coverage_state AS right_coverage_state
    FROM <SCOPED_EVENT_IDENTIFIERS> li
    JOIN <SCOPED_EVENT_IDENTIFIERS> ri
      ON li.normalized_event_id < ri.normalized_event_id
     AND li.identifier_type = ri.identifier_type
     AND li.identifier_namespace = ri.identifier_namespace
     AND li.identifier_value = ri.identifier_value
    JOIN e l ON l.normalized_event_id = li.normalized_event_id
    JOIN e r ON r.normalized_event_id = ri.normalized_event_id
    WHERE li.identifier_value IS NOT NULL
      AND r.event_time_utc >= <EDGE_WINDOW_START>(l.event_time_utc)
      AND r.event_time_utc < (<EDGE_WINDOW_END>(l.event_time_utc))
), nonexact_edges AS (
    SELECT
        l.normalized_event_id AS left_event_id,
        r.normalized_event_id AS right_event_id,
        CASE
          WHEN (l.person_key IS NOT NULL AND l.person_key = r.person_key)
            OR (l.workload_identity_key IS NOT NULL
                AND l.workload_identity_key = r.workload_identity_key)
            OR (l.resource_key IS NOT NULL AND l.resource_key = r.resource_key)
            THEN 'immutable_graph_or_resource'
          WHEN (l.source_ip IS NOT NULL AND l.source_ip = r.source_ip)
            OR (l.user_agent_family IS NOT NULL
                AND l.user_agent_family = r.user_agent_family)
            THEN 'contextual_only'
          ELSE NULL
        END AS edge_basis,
        NULL AS matched_key_type,
        NULL AS matched_key_namespace,
        NULL AS matched_key_value,
        l.provider_scope AS left_provider_scope,
        r.provider_scope AS right_provider_scope,
        l.event_time_utc AS left_time,
        r.event_time_utc AS right_time,
        l.coverage_state AS left_coverage_state,
        r.coverage_state AS right_coverage_state
    FROM e l
    JOIN e r
      ON l.normalized_event_id < r.normalized_event_id
     AND r.event_time_utc >= <EDGE_WINDOW_START>(l.event_time_utc)
     AND r.event_time_utc < (<EDGE_WINDOW_END>(l.event_time_utc))
), candidate_edges AS (
    SELECT * FROM exact_edges
    UNION ALL
    SELECT * FROM nonexact_edges WHERE edge_basis IS NOT NULL
)
SELECT *,
       CASE WHEN left_coverage_state = 'Verified'
                  AND right_coverage_state = 'Verified'
            THEN 'both_event_sources_verified'
            ELSE 'one_or_more_event_sources_not_verified' END
         AS pair_source_coverage
FROM candidate_edges
WHERE edge_basis IS NOT NULL;
