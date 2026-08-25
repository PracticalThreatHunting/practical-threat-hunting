WITH candidate_downloads AS (
    SELECT
        observation_id,
        observed_at,
        lower(host) AS host,
        normalized_path,
        path_family,
        lower(file_name) AS file_name,
        response_sha256,
        payload_sha256,
        content_type,
        response_size,
        source,
        collection_visibility
    FROM web_download_observation
    WHERE observed_at >= <ANALYSIS_CUTOFF> - INTERVAL '30 days'
      AND observed_at <  <ANALYSIS_CUTOFF>
      AND (
          path_family = '/assets/calibration/{token}/telemetryviewer.zip'
          OR payload_sha256 IN (
              'd758c45e2cf2d8f77e9ae7121799cc8d27328db22e5f1251eab6bdd223f7673e'
          )
      )
),
contacts AS (
    SELECT
        event_time,
        device_id,
        user_id,
        lower(remote_host) AS host,
        normalized_path,
        action
    FROM internal_web_contact
    WHERE event_time >= <ANALYSIS_CUTOFF> - INTERVAL '30 days'
      AND event_time <  <ANALYSIS_CUTOFF>
)
SELECT
    d.path_family,
    d.file_name,
    d.host,
    d.payload_sha256,
    d.response_sha256,
    min(d.observed_at) AS external_first_seen,
    max(d.observed_at) AS external_last_seen,
    count(DISTINCT c.device_id) AS internal_devices,
    min(c.event_time) AS internal_first_seen,
    max(c.event_time) AS internal_last_seen,
    array_agg(DISTINCT c.action) AS internal_actions,
    array_agg(DISTINCT d.source) AS evidence_sources
FROM candidate_downloads d
LEFT JOIN contacts c
  ON c.host = d.host
 AND c.normalized_path = d.normalized_path
 AND c.event_time BETWEEN d.observed_at - INTERVAL '24 hours'
                      AND d.observed_at + INTERVAL '7 days'
GROUP BY d.path_family, d.file_name, d.host,
         d.payload_sha256, d.response_sha256
ORDER BY internal_devices DESC, external_last_seen DESC;
