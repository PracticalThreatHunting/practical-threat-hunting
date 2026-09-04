-- Listing B05-H12-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_12.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH service_policy (dst_ip, dst_port, transport, expected_protocol) AS (
  VALUES
    ('203.0.113.122', 443, 'tcp', 'tls'),
    ('198.51.100.120', 8080, 'tcp', 'http'),
    ('192.0.2.120', 4443, 'tcp', 'tls')
), observations AS (
  SELECT correlation_key, ts AS event_time_utc, source, src_ip, src_port,
         e.dst_ip, e.dst_port, e.transport, coverage_state, collection_interval,
         coalesce(parser_zeek, parser_suricata) AS detected_protocol,
         p.expected_protocol
  FROM events AS e
  LEFT JOIN service_policy AS p
    ON e.dst_ip = p.dst_ip AND e.dst_port = p.dst_port AND e.transport = p.transport
  WHERE event_type = 'parser_observation'
), paired AS (
  SELECT correlation_key, src_ip, src_port, dst_ip, dst_port, transport,
         expected_protocol, min(event_time_utc) AS first_seen,
         max(event_time_utc) AS last_seen, count(*) AS event_count,
         count(DISTINCT source) AS sensor_count,
         max(CASE WHEN source = 'zeek' THEN detected_protocol END) AS zeek_protocol,
         max(CASE WHEN source = 'suricata' THEN detected_protocol END) AS suricata_protocol,
         bool_and(coverage_state = 'complete') AS coverage_complete
  FROM observations
  GROUP BY correlation_key, src_ip, src_port, dst_ip, dst_port, transport, expected_protocol
)
SELECT 'H12' AS hunt_id, correlation_key AS entity_key, first_seen, last_seen,
       event_count::BIGINT AS event_count, 1.0::DOUBLE AS score,
       CASE WHEN zeek_protocol <> suricata_protocol
         THEN concat('parser_disagreement:zeek=', zeek_protocol,
                     ';suricata=', suricata_protocol, ';packet_truth=required')
         ELSE concat('protocol_policy_mismatch:expected=', expected_protocol,
                     ';observed=', zeek_protocol, ';packet_truth=required') END AS reason
FROM paired
WHERE coverage_complete AND sensor_count >= 2
  AND zeek_protocol IS NOT NULL AND suricata_protocol IS NOT NULL
  AND (zeek_protocol <> suricata_protocol
       OR (zeek_protocol = suricata_protocol AND expected_protocol IS NOT NULL
           AND zeek_protocol <> expected_protocol))
ORDER BY first_seen, entity_key;
