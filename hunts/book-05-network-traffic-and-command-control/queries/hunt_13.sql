-- Listing B05-H13-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_13.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH complete_flows AS (
  SELECT *, (bytes_out + bytes_in)::DOUBLE / nullif(duration_s, 0) AS throughput_Bps,
         least(bytes_out, bytes_in)::DOUBLE / nullif(greatest(bytes_out, bytes_in), 0) AS duplex_ratio
  FROM events
  WHERE event_type = 'flow' AND flow_complete = true
    AND connection_state <> 'active-timeout' AND duration_s > 0
), ranked AS (
  SELECT *, count(*) OVER (PARTITION BY service) AS service_cohort_size,
         percent_rank() OVER (PARTITION BY service ORDER BY throughput_Bps) AS throughput_percentile
  FROM complete_flows
)
SELECT 'H13' AS hunt_id, src_ip AS entity_key, ts AS first_seen,
       coalesce(ts_end, ts) AS last_seen, 1::BIGINT AS event_count,
       (70.0 + (1.0 - throughput_percentile) * 16.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Complete TLS flow is persistent, low-throughput, bidirectional, and low in its service cohort.' AS reason,
       duration_s::DOUBLE AS duration_s,
       throughput_Bps::DOUBLE AS throughput_Bps,
       duplex_ratio::DOUBLE AS duplex_ratio,
       service_cohort_size::BIGINT AS service_cohort_size,
       throughput_percentile::DOUBLE AS throughput_percentile
FROM ranked
WHERE service = 'tls' AND duration_s >= 10800 AND throughput_Bps <= 2.0
  AND duplex_ratio >= 0.5 AND throughput_percentile <= 0.2;
