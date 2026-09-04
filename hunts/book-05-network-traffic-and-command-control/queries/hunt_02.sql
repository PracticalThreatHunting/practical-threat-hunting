-- Listing B05-H02-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_02.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H02' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(*) * 20.0)::DOUBLE AS score, 'DETECT' AS decision,
       'Repeated encrypted-DNS service classification on an unauthorized egress policy.' AS reason,
       app_proto AS service_class,
       CASE WHEN app_proto = 'doh' THEN 'proxy service + SNI + ALPN'
            WHEN app_proto = 'dot' THEN 'TLS service + port + ALPN'
            ELSE 'QUIC service + port + ALPN' END AS evidence_basis,
       count(DISTINCT dst_ip)::BIGINT AS destination_count
FROM events
WHERE service = 'encrypted_dns' AND app_proto IN ('doh', 'dot', 'doq')
  AND action = 'allow' AND outcome = 'established'
  AND coalesce(policy, '') <> 'approved-secure-dns'
GROUP BY src_ip, app_proto HAVING count(*) >= 4
ORDER BY service_class, entity_key;
