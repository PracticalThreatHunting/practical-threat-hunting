-- Listing B05-H05-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_05.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H05' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(*) * 7.0 + 10.0)::DOUBLE AS score, 'DETECT' AS decision,
       'Repetitive POST URI, status, MIME, and byte shape requires application-owner review.' AS reason
FROM events
WHERE event_type = 'http' AND method = 'POST' AND status_code = 200
  AND mime_type = 'application/octet-stream' AND visibility_basis IN ('plaintext-http', 'lawful-proxy-decryption')
GROUP BY src_ip, dst_ip, host
HAVING count(*) >= 10 AND count(DISTINCT uri) = 1
  AND coalesce(stddev_pop(bytes_out), 0) <= 5 AND coalesce(stddev_pop(bytes_in), 0) <= 5;
