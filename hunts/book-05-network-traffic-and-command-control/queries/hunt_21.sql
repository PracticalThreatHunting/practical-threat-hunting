-- Listing B05-H21-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_21.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H21' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT dst_ip) * 6.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Exactly mapped VPN session crosses into high-fan-out administrative east-west traffic.' AS reason
FROM events
WHERE event_type = 'flow' AND src_segment = 'vpn' AND direction = 'east-west'
  AND mapping_state = 'exact' AND vpn_session_id IS NOT NULL
GROUP BY src_ip, vpn_session_id HAVING count(DISTINCT dst_ip) >= 10;
