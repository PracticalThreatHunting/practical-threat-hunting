-- Required bounds: HUNT_START inclusive, HUNT_END exclusive,
-- ANALYSIS_CUTOFF exclusive. All participating records are frozen to them.
WITH seed_domains AS (
    SELECT n.node_value AS domain
    FROM intel_nodes n
    WHERE n.cluster_id = 'CLUSTER-LANTERN-27'
      AND n.node_type = 'domain'
      AND n.assessment_state IN ('seed', 'supported')
      AND n.valid_from < <HUNT_END>
      AND (n.valid_until IS NULL OR n.valid_until > <HUNT_START>)
      AND n.collected_at < <ANALYSIS_CUTOFF>
), seed_rr AS (
    SELECT d.query_name AS seed_domain, d.rrtype,
           d.rdata_normalized, d.first_seen, d.last_seen,
           d.source_id, d.source_record_id,
           d.source_dependency_id
    FROM dns_observations d
    JOIN seed_domains s ON s.domain = d.query_name
    LEFT JOIN shared_service_values v
      ON v.value_type = d.rrtype
     AND v.normalized_value = d.rdata_normalized
     AND (v.valid_until IS NULL OR d.first_seen < v.valid_until)
     AND (v.valid_from IS NULL OR d.last_seen >= v.valid_from)
     AND v.collected_at < <ANALYSIS_CUTOFF>
    WHERE d.rrtype IN ('NS', 'SOA_MNAME', 'SOA_RNAME_DOMAIN', 'MX')
      AND d.last_seen >= <HUNT_START>
      AND d.first_seen < <HUNT_END>
      AND d.collected_at < <ANALYSIS_CUTOFF>
      AND v.normalized_value IS NULL
), related AS (
    SELECT s.seed_domain, c.query_name AS candidate_domain,
           s.rrtype, s.rdata_normalized,
           CASE WHEN s.first_seen > c.first_seen
                THEN s.first_seen ELSE c.first_seen END AS overlap_from,
           CASE WHEN s.last_seen < c.last_seen
                THEN s.last_seen ELSE c.last_seen END AS overlap_until,
           s.source_id AS seed_source_id,
           s.source_record_id AS seed_record_id,
           s.source_dependency_id AS seed_dependency_id,
           c.source_id AS candidate_source_id,
           c.source_record_id AS candidate_record_id,
           c.source_dependency_id AS candidate_dependency_id
    FROM seed_rr s
    JOIN dns_observations c
      ON c.rrtype = s.rrtype
     AND c.rdata_normalized = s.rdata_normalized
     AND c.query_name <> s.seed_domain
     AND c.first_seen <= s.last_seen
     AND c.last_seen >= s.first_seen
     AND c.last_seen >= <HUNT_START>
     AND c.first_seen < <HUNT_END>
     AND c.collected_at < <ANALYSIS_CUTOFF>
)
SELECT *
FROM related
WHERE overlap_from <= overlap_until
ORDER BY rdata_normalized, overlap_from, candidate_domain;
