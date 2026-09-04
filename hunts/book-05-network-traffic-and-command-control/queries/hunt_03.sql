-- Listing B05-H03-SQL-01
-- Engine: DuckDB 1.4.5 LTS
-- Fixture: fixtures/generated/hunt_03.jsonl
-- Input view: events (schemas/canonical_events.sql)
-- Ground-truth fields are prohibited from analytic logic.
WITH labels AS (
  SELECT row_number() OVER () AS observation_id, src_ip, base_domain, ts, query,
         regexp_extract(query, '^([^.]+)', 1) AS first_label
  FROM events WHERE event_type = 'dns' AND qtype = 'TXT' AND query IS NOT NULL
), character_counts AS (
  SELECT observation_id, src_ip, base_domain, ts, query, first_label, character,
         count(*)::DOUBLE AS character_count
  FROM labels, unnest(string_split(first_label, '')) AS chars(character)
  GROUP BY observation_id, src_ip, base_domain, ts, query, first_label, character
), per_label AS (
  SELECT observation_id, src_ip, base_domain, ts, query, first_label,
         -sum((character_count / length(first_label))
              * log2(character_count / length(first_label))) AS entropy_bits
  FROM character_counts
  GROUP BY observation_id, src_ip, base_domain, ts, query, first_label
), aggregate_shape AS (
  SELECT src_ip, base_domain, min(ts) AS first_seen, max(ts) AS last_seen,
         count(*) AS event_count, count(DISTINCT query) AS distinct_query_count,
         count(DISTINCT query)::DOUBLE / count(*) AS unique_ratio,
         avg(length(first_label)) AS mean_label_length,
         median(length(first_label)) AS median_label_length,
         avg(entropy_bits) / 5.0 AS normalized_entropy,
         sum(floor(length(first_label) * 5.0 / 8.0))::BIGINT AS estimated_capacity_bytes
  FROM per_label GROUP BY src_ip, base_domain
)
SELECT 'H03' AS hunt_id, src_ip AS entity_key, first_seen, last_seen,
       event_count::BIGINT AS event_count,
       least(100.0, normalized_entropy * 70.0 + unique_ratio * 20.0 + 10.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Long, diverse Base32-shaped TXT labels have high computed entropy; capacity excludes protocol overhead.' AS reason,
       distinct_query_count::BIGINT AS distinct_query_count,
       unique_ratio::DOUBLE AS unique_ratio,
       mean_label_length::DOUBLE AS mean_label_length,
       median_label_length::DOUBLE AS median_label_length,
       normalized_entropy::DOUBLE AS normalized_entropy,
       estimated_capacity_bytes AS estimated_capacity_bytes
FROM aggregate_shape
WHERE event_count >= 50 AND mean_label_length >= 48
  AND normalized_entropy >= 0.7 AND unique_ratio >= 0.95;
