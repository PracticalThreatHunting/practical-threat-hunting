WITH scoped_events AS (
    SELECT normalized_event_id,
           event_time_start,
           event_time_end,
           time_precision,
           ingest_time,
           source_id,
           victim_id,
           observable_node_id,
           operation_family,
           raw_pointer
    FROM normalized_events
    WHERE COALESCE(event_time_end, event_time_start) >= <HUNT_START>
      AND event_time_start < <HUNT_END>
      AND ingest_time < <ANALYSIS_CUTOFF>
), non_temporal_edges AS (
    SELECT left_event_id, right_event_id, edge_type,
           edge_strength, source_id AS edge_source_id
    FROM event_edges
    WHERE edge_type IN (
        'same-process-entity',
        'same-synthetic-sample',
        'exact-message-url',
        'resolved-and-contacted',
        'shared-rare-infrastructure-trait',
        'same-victim-and-operational-role'
    )
      AND collected_at < <ANALYSIS_CUTOFF>
), candidate_pairs AS (
    SELECT l.normalized_event_id AS left_event_id,
           r.normalized_event_id AS right_event_id,
           e.edge_type,
           e.edge_strength,
           l.event_time_start AS left_start,
           l.event_time_end AS left_end,
           r.event_time_start AS right_start,
           r.event_time_end AS right_end,
           l.victim_id AS left_victim,
           r.victim_id AS right_victim
    FROM scoped_events l
    JOIN non_temporal_edges e
      ON e.left_event_id = l.normalized_event_id
    JOIN scoped_events r
      ON r.normalized_event_id = e.right_event_id
    WHERE r.event_time_start >= l.event_time_start - <MAX_BACKWARD_INTERVAL>
      AND r.event_time_start < COALESCE(l.event_time_end, l.event_time_start)
                               + <MAX_FORWARD_INTERVAL>
), seeded_membership AS (
    SELECT c.candidate_id,
           e.normalized_event_id,
           e.event_time_start,
           e.event_time_end,
           e.source_id,
           e.victim_id,
           e.operation_family
    FROM campaign_candidates c
    JOIN scoped_events e
      ON COALESCE(e.event_time_end, e.event_time_start) >= c.proposed_start
     AND e.event_time_start < c.proposed_end
    WHERE EXISTS (
        SELECT 1
        FROM candidate_pairs p
        WHERE (p.left_event_id = e.normalized_event_id
            OR p.right_event_id = e.normalized_event_id)
          AND p.edge_strength IN ('exact', 'corroborated')
          AND COALESCE(p.left_end, p.left_start) >= c.proposed_start
          AND p.left_start < c.proposed_end
          AND COALESCE(p.right_end, p.right_start) >= c.proposed_start
          AND p.right_start < c.proposed_end
    )
)
SELECT candidate_id,
       MIN(event_time_start) AS observed_start,
       MAX(COALESCE(event_time_end, event_time_start)) AS observed_end,
       COUNT(DISTINCT normalized_event_id) AS event_count,
       COUNT(DISTINCT source_id) AS source_count,
       COUNT(DISTINCT victim_id) AS victim_count,
       COUNT(DISTINCT operation_family) AS operation_family_count
FROM seeded_membership
GROUP BY candidate_id;
