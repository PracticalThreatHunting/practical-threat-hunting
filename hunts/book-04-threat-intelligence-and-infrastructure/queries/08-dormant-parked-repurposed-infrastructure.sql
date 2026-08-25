-- domain_state_episode is built upstream from effective-dated observations.
-- Each row covers one evidence dimension; mixed DNS/TLS/content rows are not
-- treated as a single ordered state machine.
WITH eligible AS (
    SELECT domain, dimension, episode_state,
           valid_from, valid_until, observed_at, collected_at,
           source_id, source_dependency_id, source_record_ids,
           state_basis
    FROM domain_state_episode
    WHERE observed_at < TIMESTAMP '2026-08-23 00:00:00'
      AND collected_at < TIMESTAMP '2026-08-23 00:00:00'
), prior_by_dimension AS (
    SELECT e.*,
           lag(episode_state) OVER w AS prior_state,
           lag(valid_until) OVER w AS prior_valid_until,
           lag(source_record_ids) OVER w AS prior_source_record_ids
    FROM eligible e
    WINDOW w AS (
      PARTITION BY domain, dimension ORDER BY valid_from, source_record_ids
    )
), changed_dimensions AS (
    SELECT *
    FROM prior_by_dimension
    WHERE prior_state IS NOT NULL
      AND episode_state IS DISTINCT FROM prior_state
), candidate_activation AS (
    SELECT domain,
           min(valid_from) AS activation_from,
           array_agg(DISTINCT dimension) AS changed_dimensions,
           array_agg(DISTINCT episode_state) AS new_states,
           array_agg(DISTINCT source_record_ids) AS evidence_record_sets,
           bool_or(source_dependency_id IS NULL) AS dependency_unknown
    FROM changed_dimensions
    WHERE episode_state IN ('dns_active', 'tls_observed',
                            'content_changed', 'internal_contact')
    GROUP BY domain, date_trunc('day', valid_from)
)
SELECT *
FROM candidate_activation
ORDER BY domain, activation_from;
