-- domain_network_state_snapshot contains one row per address in a composite
-- state observation. Do not derive changes by ordering individual DNS rows.
WITH point_states AS (
    SELECT domain, state_observed_at,
           array_agg(DISTINCT ip ORDER BY ip) AS address_set,
           array_agg(DISTINCT prefix ORDER BY prefix) AS prefix_set,
           array_agg(DISTINCT origin_asn ORDER BY origin_asn) AS origin_asn_set,
           array_agg(DISTINCT provider_id ORDER BY provider_id) AS provider_set,
           array_agg(DISTINCT hosting_class ORDER BY hosting_class) AS class_set,
           bool_or(anycast_state) AS anycast_seen,
           array_agg(DISTINCT source_record_id) AS source_record_ids,
           array_agg(DISTINCT source_dependency_id)
             FILTER (WHERE source_dependency_id IS NOT NULL) AS dependency_ids,
           bool_or(source_dependency_id IS NULL) AS dependency_unknown
    FROM domain_network_state_snapshot
    WHERE cluster_id = 'CLUSTER-LANTERN-27'
      AND collected_at < TIMESTAMP '2026-08-24 00:00:00'
      AND rrtype IN ('A', 'AAAA')
    GROUP BY domain, state_observed_at
), compared AS (
    SELECT p.*,
           lag(address_set) OVER w AS prior_address_set,
           lag(prefix_set) OVER w AS prior_prefix_set,
           lag(origin_asn_set) OVER w AS prior_origin_asn_set,
           lag(provider_set) OVER w AS prior_provider_set,
           lag(class_set) OVER w AS prior_class_set,
           lag(state_observed_at) OVER w AS prior_state_at
    FROM point_states p
    WINDOW w AS (PARTITION BY domain ORDER BY state_observed_at)
)
SELECT domain, prior_state_at, state_observed_at,
       prior_address_set, address_set,
       prior_prefix_set, prefix_set,
       prior_origin_asn_set, origin_asn_set,
       prior_provider_set, provider_set,
       prior_class_set, class_set,
       anycast_seen, source_record_ids, dependency_ids, dependency_unknown
FROM compared
WHERE prior_state_at IS NOT NULL
  AND (address_set IS DISTINCT FROM prior_address_set
    OR prefix_set IS DISTINCT FROM prior_prefix_set
    OR origin_asn_set IS DISTINCT FROM prior_origin_asn_set
    OR provider_set IS DISTINCT FROM prior_provider_set
    OR class_set IS DISTINCT FROM prior_class_set)
ORDER BY domain, state_observed_at;
