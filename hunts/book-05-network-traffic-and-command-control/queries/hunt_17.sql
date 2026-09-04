-- Listing B05-H17-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_17.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H17' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT channel) * 25.0 + count_if(outcome = 'blocked') * 10.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Coherent destination context switches across three channels after blocked attempts.' AS reason
FROM events
WHERE event_type = 'channel_event' AND correlation_key IS NOT NULL
GROUP BY src_ip, dst_ip, correlation_key
HAVING count(DISTINCT channel) >= 3 AND count_if(outcome = 'blocked') >= 2
   AND count_if(outcome = 'established') >= 1
   AND epoch(max(ts)) - epoch(min(ts)) <= 180;
