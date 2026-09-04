-- Listing B05-H01-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_01.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH candidates AS (
  SELECT * FROM events
  WHERE event_type = 'dns' AND direction = 'outbound'
    AND dst_port = 53 AND transport IN ('udp', 'tcp')
    AND action = 'allow' AND outcome = 'established'
    AND connection_state = 'complete' AND query IS NOT NULL
    AND mapping_state = 'exact' AND dst_ip <> '10.50.0.53'
)
SELECT 'H01' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(*) * 20.0)::DOUBLE AS score, 'DETECT' AS decision,
       'Established DNS path bypassed the role resolver; compromise is not established.' AS reason,
       count_if(transport = 'udp')::BIGINT AS udp_exchanges,
       count_if(transport = 'tcp')::BIGINT AS tcp_exchanges,
       count(DISTINCT dst_ip)::BIGINT AS resolver_count,
       min(mapping_state) AS attribution_state
FROM candidates GROUP BY src_ip HAVING count(*) >= 2;
