-- Listing B05-H18-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_18.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H18' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT dst_ip) * 3.0 + count(DISTINCT dst_port) * 5.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Workstation shows broad east-west destination and administrative-port fan-out.' AS reason
FROM events
WHERE event_type = 'flow' AND direction = 'east-west'
  AND src_role NOT IN ('vulnerability_scanner', 'load_balancer', 'orchestrator', 'monitoring_server')
GROUP BY src_ip
HAVING count(DISTINCT dst_ip) >= 20 AND count(DISTINCT dst_port) >= 3;
