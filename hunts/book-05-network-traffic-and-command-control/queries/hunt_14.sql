-- Listing B05-H14-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_14.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH echo AS (
  SELECT CASE WHEN icmp_type = 8 THEN src_ip ELSE dst_ip END AS client_ip,
         ts, icmp_type, icmp_id, icmp_seq, payload_len
  FROM events
  WHERE event_type = 'icmp' AND icmp_version = 4 AND icmp_type IN (0, 8)
    AND coverage_state = 'complete' AND coalesce(policy, '') <> 'approved-monitoring'
), sessions AS (
  SELECT client_ip, icmp_id, min(ts) AS first_seen, max(ts) AS last_seen,
         count_if(icmp_type = 8) AS request_count,
         count_if(icmp_type = 0) AS reply_count,
         avg(payload_len) FILTER (WHERE icmp_type = 8) AS mean_request_payload,
         count(DISTINCT icmp_seq) FILTER (WHERE icmp_type = 8) AS distinct_request_sequences,
         min(icmp_seq) FILTER (WHERE icmp_type = 8) AS minimum_sequence,
         max(icmp_seq) FILTER (WHERE icmp_type = 8) AS maximum_sequence
  FROM echo GROUP BY client_ip, icmp_id
)
SELECT 'H14' AS hunt_id, client_ip AS entity_key, first_seen,
       last_seen, (request_count + reply_count)::BIGINT AS event_count,
       least(100.0, request_count * 8.0 + mean_request_payload / 16.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Large sequential ICMPv4 echo requests have weak reply symmetry outside the diagnostic policy.' AS reason,
       request_count::BIGINT AS request_count, reply_count::BIGINT AS reply_count,
       reply_count::DOUBLE / nullif(request_count, 0) AS reply_request_ratio,
       mean_request_payload::DOUBLE AS mean_request_payload,
       (distinct_request_sequences = maximum_sequence - minimum_sequence + 1) AS sequence_contiguous
FROM sessions
WHERE request_count >= 8 AND mean_request_payload >= 128
  AND reply_count::DOUBLE / nullif(request_count, 0) < 0.5
  AND distinct_request_sequences = maximum_sequence - minimum_sequence + 1;
