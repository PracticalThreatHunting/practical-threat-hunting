WITH observed AS (
    SELECT m.message_id, m.received_at, m.recipient_id,
           lower(m.provider_domain) AS provider_domain,
           m.service_key_type, nullif(m.service_key, '') AS service_key,
           m.normalized_path, m.url_fingerprint, m.redirect_terminal_host
    FROM message_url m
    WHERE m.received_at >= <ANALYSIS_CUTOFF> - INTERVAL '30 days'
      AND m.received_at <  <ANALYSIS_CUTOFF>
      AND lower(m.provider_domain) IN (
          'cdn-platform.example', 'web-service.example'
      )
), inventory_match_counts AS (
    SELECT o.*,
           count(i.inventory_id) AS inventory_matches,
           min(i.owner) AS owner,
           min(i.approved_purpose) AS approved_purpose
    FROM observed o
    LEFT JOIN service_object_inventory i
      ON i.provider_domain = o.provider_domain
     AND i.service_key_type = o.service_key_type
     AND i.service_key = o.service_key
     AND o.received_at >= i.valid_from
     AND (i.valid_until IS NULL OR o.received_at < i.valid_until)
    GROUP BY o.message_id, o.received_at, o.recipient_id,
             o.provider_domain, o.service_key_type, o.service_key,
             o.normalized_path, o.url_fingerprint,
             o.redirect_terminal_host
), classified AS (
    SELECT *, CASE
      WHEN service_key IS NULL THEN 'inventory_unknown'
      WHEN inventory_matches = 0 THEN 'not_approved'
      WHEN inventory_matches = 1 THEN 'approved'
      ELSE 'inventory_overlap_error'
    END AS inventory_state
    FROM inventory_match_counts
)
SELECT c.provider_domain, c.service_key_type, c.service_key,
       c.inventory_state,
       count(DISTINCT c.message_id) AS messages,
       count(DISTINCT c.recipient_id) AS recipients,
       count(DISTINCT w.device_id) AS contacting_devices,
       min(c.received_at) AS first_message,
       max(c.received_at) AS last_message,
       array_agg(DISTINCT c.redirect_terminal_host) AS terminal_hosts,
       array_agg(DISTINCT c.url_fingerprint) AS url_fingerprints
FROM classified c
LEFT JOIN internal_web_contact w
  ON c.service_key IS NOT NULL
 AND w.provider_domain = c.provider_domain
 AND w.service_key_type = c.service_key_type
 AND w.service_key = c.service_key
 AND w.event_time >= c.received_at - INTERVAL '1 hour'
 AND w.event_time <  c.received_at + INTERVAL '7 days'
 AND w.event_time <  <ANALYSIS_CUTOFF>
GROUP BY c.provider_domain, c.service_key_type,
         c.service_key, c.inventory_state
ORDER BY contacting_devices DESC, recipients DESC;
