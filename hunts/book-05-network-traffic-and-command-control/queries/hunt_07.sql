-- Listing B05-H07-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_07.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH ordered AS (
  SELECT src_ip, dst_ip, ts, bytes_out, bytes_in,
         epoch(ts) - epoch(lag(ts) OVER (PARTITION BY src_ip, dst_ip ORDER BY ts)) AS delta_s
  FROM events
  WHERE event_type = 'flow' AND service = 'tls' AND app_proto = 'tls'
    AND coverage_state = 'complete'
), per_host AS (
  SELECT src_ip, dst_ip, min(ts) AS first_seen, max(ts) AS last_seen,
         count(*) AS observations, median(delta_s) AS median_delta_s,
         coalesce(stddev_pop(delta_s), 0) / nullif(avg(delta_s), 0) AS cadence_cv,
         avg(bytes_out) AS mean_bytes_out, avg(bytes_in) AS mean_bytes_in,
         coalesce(stddev_pop(bytes_out), 0) AS sd_bytes_out,
         coalesce(stddev_pop(bytes_in), 0) AS sd_bytes_in
  FROM ordered GROUP BY src_ip, dst_ip HAVING count(*) >= 8
), cohorts AS (
  SELECT dst_ip, min(first_seen) AS first_seen, max(last_seen) AS last_seen,
         sum(observations) AS event_count, count(*) AS host_count,
         median(median_delta_s) AS cohort_median_delta_s,
         coalesce(stddev_pop(median_delta_s), 0) AS host_cadence_spread_s,
         max(cadence_cv) AS worst_host_cadence_cv,
         avg(mean_bytes_out) AS cohort_mean_bytes_out,
         avg(mean_bytes_in) AS cohort_mean_bytes_in,
         max(sd_bytes_out) AS worst_sd_bytes_out,
         max(sd_bytes_in) AS worst_sd_bytes_in
  FROM per_host GROUP BY dst_ip
)
SELECT 'H07' AS hunt_id, dst_ip AS entity_key, first_seen,
       last_seen, event_count::BIGINT AS event_count,
       least(100.0, host_count * 25.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'A small cross-host cohort shares destination, stable cadence, and stable balanced byte shape.' AS reason,
       host_count::BIGINT AS host_count,
       cohort_median_delta_s::DOUBLE AS cohort_median_delta_s,
       host_cadence_spread_s::DOUBLE AS host_cadence_spread_s,
       worst_host_cadence_cv::DOUBLE AS worst_host_cadence_cv,
       cohort_mean_bytes_out::DOUBLE AS cohort_mean_bytes_out,
       cohort_mean_bytes_in::DOUBLE AS cohort_mean_bytes_in,
       worst_sd_bytes_out::DOUBLE AS worst_sd_bytes_out,
       worst_sd_bytes_in::DOUBLE AS worst_sd_bytes_in
FROM cohorts
WHERE host_count BETWEEN 3 AND 6 AND event_count >= 24
  AND cohort_median_delta_s BETWEEN 290 AND 310
  AND host_cadence_spread_s <= 5 AND worst_host_cadence_cv <= 0.05
  AND cohort_mean_bytes_out BETWEEN 150 AND 300
  AND cohort_mean_bytes_in BETWEEN 150 AND 300
  AND worst_sd_bytes_out <= 5 AND worst_sd_bytes_in <= 5;
