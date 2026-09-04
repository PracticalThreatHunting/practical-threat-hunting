-- Listing B05-H23-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_23.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H23' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(coalesce(ts_end, ts)) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, 60.0 + bytes_out / 1073741824.0 * 5.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Unsampled complete flow shows multi-GiB outbound volume and strong upload asymmetry.' AS reason
FROM events
WHERE event_type = 'flow' AND flow_complete = true AND sample_rate = 1
  AND counter_layer = 'observed_ip' AND bytes_out >= 4294967296
  AND bytes_out::DOUBLE / nullif(bytes_in, 0) >= 10
  AND src_role <> 'backup_server'
GROUP BY src_ip, bytes_out;
