WITH params AS (
    SELECT TIMESTAMP '2026-08-13 00:00:00' AS analysis_cutoff,
           'L27-2026-08-12'::text AS membership_version
), ranked_snapshots AS (
    SELECT r.*,
           ROW_NUMBER() OVER (
               PARTITION BY r.domain
               ORDER BY r.snapshot_at DESC, r.collected_at DESC
           ) AS snapshot_rank
    FROM registration_snapshots r
    CROSS JOIN params p
    WHERE r.snapshot_at < p.analysis_cutoff
      AND r.collected_at < p.analysis_cutoff
), current_at_cutoff AS (
    SELECT domain, registrar_id, registration_event_at,
           registration_time_precision, source_id,
           source_record_id, collected_at
    FROM ranked_snapshots
    WHERE snapshot_rank = 1
), seeds AS (
    SELECT m.node_value AS domain
    FROM campaign_membership_snapshot m
    CROSS JOIN params p
    WHERE m.cluster_id = 'CLUSTER-LANTERN-27'
      AND m.membership_version = p.membership_version
      AND m.membership_status IN ('seed', 'supported')
      AND m.collected_at < p.analysis_cutoff
), cohort_candidates AS (
    SELECT s.domain AS seed_domain,
           c.domain AS candidate_domain,
           s.registrar_id,
           s.registration_event_at AS seed_registered_at,
           c.registration_event_at AS candidate_registered_at,
           s.registration_time_precision AS seed_time_precision,
           c.registration_time_precision AS candidate_time_precision,
           ABS(EXTRACT(EPOCH FROM
               (c.registration_event_at - s.registration_event_at))) AS gap_seconds,
           s.source_id AS seed_source_id,
           s.source_record_id AS seed_source_record_id,
           c.source_id AS candidate_source_id,
           c.source_record_id AS candidate_source_record_id
    FROM current_at_cutoff s
    JOIN seeds x ON x.domain = s.domain
    JOIN current_at_cutoff c
      ON c.registrar_id = s.registrar_id
     AND c.domain <> s.domain
     AND c.registration_event_at >= s.registration_event_at - INTERVAL '24 hours'
     AND c.registration_event_at <  s.registration_event_at + INTERVAL '24 hours'
)
SELECT cc.*, dc.brand_feature_count, dc.lexical_family
FROM cohort_candidates cc
JOIN domain_candidates dc ON dc.domain = cc.candidate_domain
CROSS JOIN params p
WHERE dc.brand_feature_count > 0
  AND dc.collected_at < p.analysis_cutoff
  AND cc.seed_time_precision IN ('second', 'minute', 'hour')
  AND cc.candidate_time_precision IN ('second', 'minute', 'hour');
