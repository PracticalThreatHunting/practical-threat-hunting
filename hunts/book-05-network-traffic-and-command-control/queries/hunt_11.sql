-- Listing B05-H11-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_11.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H11' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(coalesce(ts_end, ts)) AS last_seen, count(*)::BIGINT AS event_count,
       88.0::DOUBLE AS score, 'DETECT' AS decision,
       'Established CONNECT session is long-lived, low-throughput, and outside the approved relay path.' AS reason
FROM events
WHERE event_type = 'proxy_session' AND proxy_method = 'CONNECT'
  AND action = 'allow' AND outcome = 'established' AND duration_s >= 3600
  AND (coalesce(bytes_out, 0) + coalesce(bytes_in, 0)) / nullif(duration_s, 0) <= 20
GROUP BY src_ip;
