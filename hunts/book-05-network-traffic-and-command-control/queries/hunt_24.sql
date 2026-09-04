-- Listing B05-H24-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_24.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H24' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT CAST(ts AS DATE)) * 6.0 + sum(bytes_out) / 10485760.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Small outbound chunks accumulate persistently across days with complete collection.' AS reason
FROM events
WHERE event_type = 'flow' AND coverage_state = 'complete'
  AND collection_interval = 'present' AND bytes_out BETWEEN 1048576 AND 10485760
  AND bytes_out::DOUBLE / nullif(bytes_in, 0) >= 10
GROUP BY src_ip
HAVING count(*) >= 28 AND count(DISTINCT CAST(ts AS DATE)) >= 8
   AND sum(bytes_out) >= 83886080;
