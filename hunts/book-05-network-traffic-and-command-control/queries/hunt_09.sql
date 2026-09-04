-- Listing B05-H09-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_09.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
SELECT 'H09' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count_if(app_proto = 'quic') * 18.0 + 20.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Unsanctioned QUIC attempts and same-destination TCP fallback alter visibility; QUIC is not inherently malicious.' AS reason
FROM events
WHERE dst_port = 443 AND channel IN ('quic', 'https')
GROUP BY src_ip, dst_ip
HAVING count_if(app_proto = 'quic') >= 4
   AND count_if(transport = 'tcp' AND app_proto = 'tls') >= 1
   AND coalesce(max(policy), '') <> 'approved-browser-http3'
   AND epoch(max(ts)) - epoch(min(ts)) <= 600;
