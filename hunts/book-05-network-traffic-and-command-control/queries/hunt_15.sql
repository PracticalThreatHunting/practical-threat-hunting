-- Listing B05-H15-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_15.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH authorized_tunnels (src_role, dst_ip, ip_protocol_number, valid_from, valid_to) AS (
  VALUES ('sdwan_gateway', '198.51.100.150', 47,
          TIMESTAMP '2026-01-01 00:00:00', TIMESTAMP '2027-01-01 00:00:00')
), observations AS (
  SELECT e.*, a.src_role AS authorized_role
  FROM events AS e
  LEFT JOIN authorized_tunnels AS a
    ON e.src_role = a.src_role AND e.dst_ip = a.dst_ip
   AND e.ip_protocol_number = a.ip_protocol_number
   AND e.ts >= a.valid_from AND e.ts < a.valid_to
)
SELECT 'H15' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count, 85.0::DOUBLE AS score,
       'DETECT' AS decision,
       'Observed encapsulation has no effective-dated match in the authorized tunnel inventory.' AS reason,
       min(ip_protocol_number)::BIGINT AS ip_protocol_number,
       min(tunnel_type) AS observed_tunnel_type,
       'no_inventory_match' AS authorization_state
FROM observations
WHERE event_type = 'network_layer' AND ip_protocol_number IN (4, 41, 47)
  AND authorized_role IS NULL AND coverage_state = 'complete' AND action = 'allow'
GROUP BY src_ip;
