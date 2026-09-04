-- Listing B05-H22-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_22.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H22' AS hunt_id, dst_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count, 92.0::DOUBLE AS score,
       'DETECT' AS decision,
       'Visible inbound file metadata combines executable MIME with a deceptive filename.' AS reason
FROM events
WHERE event_type = 'file' AND direction = 'inbound'
  AND visibility_basis IN ('plaintext-file-metadata', 'lawful-proxy-decryption')
  AND filename IS NOT NULL AND mime_type IN ('application/x-dosexec', 'application/x-executable')
  AND lower(filename) LIKE '%.exe' AND dst_role = 'workstation'
GROUP BY dst_ip;
