WITH params AS (
    SELECT TIMESTAMP '2026-08-20 00:00:00' AS analysis_cutoff,
           TIMESTAMP '2026-08-01 00:00:00' AS deployment_start,
           'L27-2026-08-19'::text AS membership_version
), seed_domains AS (
    SELECT n.node_value AS domain
    FROM campaign_membership_snapshot m
    JOIN intel_nodes n ON n.node_id = m.node_id
    CROSS JOIN params p
    WHERE m.cluster_id = 'CLUSTER-LANTERN-27'
      AND m.membership_version = p.membership_version
      AND m.membership_status IN ('seed', 'supported')
      AND m.collected_at < p.analysis_cutoff
      AND n.node_type = 'domain'
      AND n.first_collected_at < p.analysis_cutoff
), seed_certificates AS (
    SELECT DISTINCT c.cert_sha256
    FROM certificate_san_names c
    JOIN seed_domains s ON s.domain = c.san_dns_name
    CROSS JOIN params p
    WHERE c.ct_entry_timestamp < p.analysis_cutoff
      AND c.collected_at < p.analysis_cutoff
), related_names AS (
    SELECT c.cert_sha256, c.san_dns_name, c.is_wildcard,
           c.not_before, c.not_after, c.ct_log_id,
           c.ct_entry_timestamp, c.collected_at,
           c.source_id, c.source_record_id
    FROM certificate_san_names c
    JOIN seed_certificates s ON s.cert_sha256 = c.cert_sha256
    CROSS JOIN params p
    WHERE c.ct_entry_timestamp < p.analysis_cutoff
      AND c.collected_at < p.analysis_cutoff
), deployments AS (
    SELECT t.cert_sha256, t.endpoint_ip, t.endpoint_port,
           t.observed_at, t.collected_at, t.vantage_id,
           t.source_id AS tls_source_id,
           t.source_record_id AS tls_source_record_id
    FROM passive_tls_observations t
    JOIN seed_certificates s ON s.cert_sha256 = t.cert_sha256
    CROSS JOIN params p
    WHERE t.observed_at >= p.deployment_start
      AND t.observed_at < p.analysis_cutoff
      AND t.collected_at < p.analysis_cutoff
)
SELECT n.cert_sha256, n.san_dns_name, n.is_wildcard,
       n.not_before, n.not_after, n.ct_log_id,
       n.ct_entry_timestamp, n.collected_at AS ct_collected_at,
       n.source_id AS ct_source_id,
       n.source_record_id AS ct_source_record_id,
       d.endpoint_ip, d.endpoint_port, d.observed_at,
       d.collected_at AS tls_collected_at, d.vantage_id,
       d.tls_source_id, d.tls_source_record_id
FROM related_names n
LEFT JOIN deployments d ON d.cert_sha256 = n.cert_sha256
ORDER BY n.cert_sha256, n.san_dns_name, d.observed_at;
