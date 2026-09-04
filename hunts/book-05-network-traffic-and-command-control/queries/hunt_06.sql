-- Listing B05-H06-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_06.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH ordered AS (
  SELECT src_ip, dst_ip, ts,
         epoch(ts) - epoch(lag(ts) OVER (PARTITION BY src_ip, dst_ip ORDER BY ts)) AS delta_s
  FROM events
  WHERE event_type = 'flow' AND app_proto = 'tls'
    AND coverage_state = 'complete' AND collection_interval = 'present'
), centers AS (
  SELECT src_ip, dst_ip, median(delta_s) AS median_delta_s
  FROM ordered GROUP BY src_ip, dst_ip
), stats AS (
  SELECT src_ip, dst_ip, min(ts) AS first_seen, max(ts) AS last_seen,
         count(*) AS event_count, max(centers.median_delta_s) AS median_delta_s,
         median(abs(ordered.delta_s - centers.median_delta_s)) AS mad_delta_s,
         stddev_pop(delta_s) / nullif(avg(delta_s), 0) AS interval_cv
  FROM ordered JOIN centers USING (src_ip, dst_ip)
  GROUP BY src_ip, dst_ip
)
SELECT 'H06' AS hunt_id, src_ip AS entity_key, first_seen, last_seen,
       event_count::BIGINT AS event_count, greatest(0.0, least(100.0, 100.0 * (1.0 - interval_cv)))::DOUBLE AS score,
       'DETECT' AS decision,
       'Jitter-tolerant recurrence remains stable after coverage checks.' AS reason,
       median_delta_s::DOUBLE AS median_delta_s,
       mad_delta_s::DOUBLE AS mad_delta_s,
       interval_cv::DOUBLE AS interval_cv,
       'complete' AS analyzed_coverage
FROM stats
WHERE event_count >= 12 AND median_delta_s BETWEEN 45 AND 75 AND interval_cv <= 0.25;
