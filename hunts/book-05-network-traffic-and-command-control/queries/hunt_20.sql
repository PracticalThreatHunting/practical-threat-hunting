-- Listing B05-H20-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_20.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H20' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count, 84.0::DOUBLE AS score,
       'DETECT' AS decision,
       'Peer-to-peer workstation remote administration bypasses the jump-host topology.' AS reason
FROM events
WHERE event_type = 'remote_admin' AND direction = 'east-west'
  AND src_role = 'workstation' AND dst_role = 'workstation'
  AND remote_admin_proto IN ('rdp', 'vnc', 'winrm', 'ssh') AND action = 'allow'
GROUP BY src_ip;
