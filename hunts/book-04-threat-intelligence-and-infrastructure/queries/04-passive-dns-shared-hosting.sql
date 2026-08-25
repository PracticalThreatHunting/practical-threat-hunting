-- Required bounds: HUNT_START inclusive, HUNT_END exclusive,
-- ANALYSIS_CUTOFF exclusive.
WITH cluster_domains AS (
    SELECT n.node_value AS domain
    FROM intel_nodes n
    WHERE n.cluster_id = 'CLUSTER-LANTERN-27'
      AND n.node_type = 'domain'
      AND n.assessment_state IN ('seed', 'supported', 'monitor')
      AND n.valid_from < <HUNT_END>
      AND (n.valid_until IS NULL OR n.valid_until > <HUNT_START>)
      AND n.collected_at < <ANALYSIS_CUTOFF>
), intervals AS (
    SELECT r.source_name AS domain, r.target_value AS destination_ip,
           r.valid_from_estimate, r.valid_until_estimate,
           r.interval_confidence, r.source_id, r.source_record_ids,
           r.shared_service_class
    FROM resolution_intervals r
    JOIN cluster_domains c ON c.domain = r.source_name
    WHERE r.relationship_type IN ('A', 'AAAA', 'CNAME_TO_ADDRESS_PATH')
      AND r.valid_until_estimate > <HUNT_START>
      AND r.valid_from_estimate < <HUNT_END>
      AND r.collected_at < <ANALYSIS_CUTOFF>
), exact_fqdn AS (
    SELECT e.event_time, e.source_asset, e.source_user,
           e.destination_fqdn, e.destination_ip, e.event_action,
           e.sensor, e.raw_event_id, i.domain,
           'exact_fqdn' AS match_type,
           i.source_id, i.source_record_ids,
           i.interval_confidence, i.shared_service_class
    FROM normalized_network_events e
    JOIN intervals i
      ON e.destination_fqdn = i.domain
     AND e.event_time >= i.valid_from_estimate
     AND e.event_time <  i.valid_until_estimate
    WHERE e.event_time >= <HUNT_START>
      AND e.event_time < <HUNT_END>
      AND e.collected_at < <ANALYSIS_CUTOFF>
), interval_ip AS (
    SELECT e.event_time, e.source_asset, e.source_user,
           e.destination_fqdn, e.destination_ip, e.event_action,
           e.sensor, e.raw_event_id, i.domain,
           'ip_in_observed_interval' AS match_type,
           i.source_id, i.source_record_ids,
           i.interval_confidence, i.shared_service_class
    FROM normalized_network_events e
    JOIN intervals i
      ON e.destination_ip = i.destination_ip
     AND e.event_time >= i.valid_from_estimate
     AND e.event_time <  i.valid_until_estimate
    WHERE e.destination_fqdn IS NULL
      AND e.event_time >= <HUNT_START>
      AND e.event_time < <HUNT_END>
      AND e.collected_at < <ANALYSIS_CUTOFF>
)
SELECT * FROM exact_fqdn
UNION ALL
SELECT * FROM interval_ip
ORDER BY event_time;
