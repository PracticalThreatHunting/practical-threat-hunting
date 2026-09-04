-- Listing B05-H19-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_19.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H19' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT dst_ip) * 15.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Workstation fans out ADMIN$ transfers with service-control RPC metadata; file intent is unknown.' AS reason
FROM events
WHERE event_type = 'smb' AND direction = 'east-west' AND share_name = 'ADMIN$'
  AND rpc_operation = 'svcctl.CreateServiceW' AND src_role = 'workstation'
GROUP BY src_ip HAVING count(DISTINCT dst_ip) >= 5;
