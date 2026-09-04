-- Listing B05-H10-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_10.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H10' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count, 90.0::DOUBLE AS score,
       'DETECT' AS decision,
       'Lawfully visible outer name and HTTP authority differ without a known proxy rewrite.' AS reason
FROM events
WHERE event_type = 'http' AND visibility_basis = 'lawful-proxy-decryption'
  AND sni IS NOT NULL AND authority IS NOT NULL
  AND lower(sni) <> lower(authority) AND proxy_rewrite = false
GROUP BY src_ip;
