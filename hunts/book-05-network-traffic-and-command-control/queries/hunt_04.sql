-- Listing B05-H04-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_04.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH ordered AS (
  SELECT src_ip, base_domain, ts, rcode, sequential_label,
         epoch(ts) - epoch(lag(ts) OVER (PARTITION BY src_ip, base_domain ORDER BY ts)) AS delta_s
  FROM events
  WHERE event_type = 'dns' AND coverage_state = 'complete'
    AND collection_interval = 'present'
), centers AS (
  SELECT src_ip, base_domain, median(delta_s) AS median_delta_s
  FROM ordered GROUP BY src_ip, base_domain
), scored AS (
  SELECT src_ip, base_domain, min(ts) AS first_seen, max(ts) AS last_seen,
         count(*) AS event_count, max(centers.median_delta_s) AS median_delta_s,
         median(abs(ordered.delta_s - centers.median_delta_s)) AS mad_delta_s,
         count(rcode) AS observed_response_count,
         count_if(rcode = 'NXDOMAIN') AS nxdomain_count,
         count_if(rcode = 'NXDOMAIN')::DOUBLE / nullif(count(rcode), 0) AS failure_ratio,
         avg(CASE WHEN sequential_label THEN 1.0 ELSE 0.0 END) AS sequential_ratio,
         epoch(max(ts)) - epoch(min(ts)) AS span_s
  FROM ordered JOIN centers USING (src_ip, base_domain)
  GROUP BY src_ip, base_domain
)
SELECT 'H04' AS hunt_id, src_ip AS entity_key, first_seen, last_seen,
       event_count::BIGINT AS event_count, least(100.0, failure_ratio * 45 + sequential_ratio * 45
         + least(median_delta_s / 7200.0, 1.0) * 10)::DOUBLE AS score,
       'DETECT' AS decision,
       'Sparse, failure-heavy sequential DNS persists with complete collection.' AS reason,
       median_delta_s::DOUBLE AS median_delta_s,
       mad_delta_s::DOUBLE AS mad_delta_s,
       observed_response_count::BIGINT AS observed_response_count,
       nxdomain_count::BIGINT AS nxdomain_count,
       failure_ratio::DOUBLE AS failure_ratio,
       sequential_ratio::DOUBLE AS sequential_ratio,
       span_s::DOUBLE AS span_s,
       'complete' AS analyzed_coverage
FROM scored
WHERE event_count = 36 AND median_delta_s BETWEEN 1020 AND 1380
  AND failure_ratio >= 0.8 AND sequential_ratio >= 0.9;
