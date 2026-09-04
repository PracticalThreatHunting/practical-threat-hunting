-- Listing B05-H16-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_16.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH approved_services (src_role, dst_ip, dst_port, service, valid_from, valid_to) AS (
  VALUES ('workstation', '198.51.100.160', 22, 'ssh',
          TIMESTAMP '2026-01-01 00:00:00', TIMESTAMP '2027-01-01 00:00:00')
), sessions AS (
  SELECT e.*, a.dst_ip AS approved_destination
  FROM events AS e
  LEFT JOIN approved_services AS a
    ON e.src_role = a.src_role AND e.dst_ip = a.dst_ip AND e.dst_port = a.dst_port
   AND e.service = a.service AND e.ts >= a.valid_from AND e.ts < a.valid_to
)
SELECT 'H16' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(coalesce(ts_end, ts)) AS last_seen, count(*)::BIGINT AS event_count,
       82.0::DOUBLE AS score, 'DETECT' AS decision,
       'Long complete outbound SSH has no effective-dated service-inventory match; forwarding is unproven.' AS reason,
       min(duration_s)::DOUBLE AS minimum_duration_s,
       sum(bytes_out)::BIGINT AS bytes_out,
       sum(bytes_in)::BIGINT AS bytes_in,
       'no_inventory_match' AS authorization_state
FROM sessions
WHERE event_type = 'ssh' AND direction = 'outbound' AND app_proto = 'ssh'
  AND src_role = 'workstation' AND duration_s >= 900 AND flow_complete = true
  AND bytes_out > 0 AND bytes_in > 0 AND action = 'allow' AND approved_destination IS NULL
GROUP BY src_ip;
