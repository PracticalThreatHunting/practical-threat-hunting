-- Listing B05-H08-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_08.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH scored AS (
  SELECT *, (CASE WHEN cert_self_signed THEN 30 ELSE 0 END)
           + (CASE WHEN sni_cert_match = false THEN 30 ELSE 0 END)
           + (CASE WHEN alpn LIKE 'unknown%' THEN 20 ELSE 0 END)
           + (CASE WHEN cert_valid_days > 825 THEN 20 ELSE 0 END) AS coherence_score
  FROM events WHERE event_type = 'tls' AND coverage_state = 'complete'
    AND coalesce(policy, '') <> 'approved-tls-inspection'
)
SELECT 'H08' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       max(coherence_score)::DOUBLE AS score, 'DETECT' AS decision,
       'TLS name, certificate, ALPN, and lifetime are mutually incoherent after inspection-policy gating; fingerprint is not identity.' AS reason,
       max(CASE WHEN cert_self_signed THEN 1 ELSE 0 END)::BIGINT AS self_signed_observations,
       max(CASE WHEN sni_cert_match = false THEN 1 ELSE 0 END)::BIGINT AS name_mismatch_observations,
       max(cert_valid_days)::BIGINT AS maximum_validity_days,
       max(alpn) AS observed_alpn
FROM scored GROUP BY src_ip HAVING max(coherence_score) >= 70;
