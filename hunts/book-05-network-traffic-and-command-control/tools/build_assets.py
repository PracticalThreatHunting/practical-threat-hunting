#!/usr/bin/env python3
"""Materialize the reviewed SQL listings and canonical schema.

This is a maintainer utility.  It does not download data, open sockets, or
change golden results.  The ordinary reader workflow uses book05_lab.verify.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RESULT_COLUMNS = [
    "hunt_id", "entity_key", "first_seen", "last_seen", "event_count",
    "score", "decision", "reason",
]

QUERIES: dict[int, str] = {
1: """
WITH candidates AS (
  SELECT * FROM events
  WHERE event_type = 'dns' AND direction = 'outbound'
    AND dst_port = 53 AND transport IN ('udp', 'tcp')
    AND action = 'allow' AND outcome = 'established'
    AND connection_state = 'complete' AND query IS NOT NULL
    AND mapping_state = 'exact' AND dst_ip <> '10.50.0.53'
)
SELECT 'H01' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(*) * 20.0)::DOUBLE AS score, 'DETECT' AS decision,
       'Established DNS path bypassed the role resolver; compromise is not established.' AS reason,
       count_if(transport = 'udp')::BIGINT AS udp_exchanges,
       count_if(transport = 'tcp')::BIGINT AS tcp_exchanges,
       count(DISTINCT dst_ip)::BIGINT AS resolver_count,
       min(mapping_state) AS attribution_state
FROM candidates GROUP BY src_ip HAVING count(*) >= 2;
""",
2: """
SELECT 'H02' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(*) * 20.0)::DOUBLE AS score, 'DETECT' AS decision,
       'Repeated encrypted-DNS service classification on an unauthorized egress policy.' AS reason,
       app_proto AS service_class,
       CASE WHEN app_proto = 'doh' THEN 'proxy service + SNI + ALPN'
            WHEN app_proto = 'dot' THEN 'TLS service + port + ALPN'
            ELSE 'QUIC service + port + ALPN' END AS evidence_basis,
       count(DISTINCT dst_ip)::BIGINT AS destination_count
FROM events
WHERE service = 'encrypted_dns' AND app_proto IN ('doh', 'dot', 'doq')
  AND action = 'allow' AND outcome = 'established'
  AND coalesce(policy, '') <> 'approved-secure-dns'
GROUP BY src_ip, app_proto HAVING count(*) >= 4
ORDER BY service_class, entity_key;
""",
3: """
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
""",
4: """
WITH ordered AS (
  SELECT src_ip, base_domain, ts, rcode, sequential_label,
         epoch(ts) - epoch(lag(ts) OVER (PARTITION BY src_ip, base_domain ORDER BY ts)) AS delta_s
  FROM events
  WHERE event_type = 'dns' AND coverage_state = 'complete'
    AND collection_interval = 'present'
), centers AS (
  SELECT src_ip, base_domain, median(delta_s) AS median_delta_s
  FROM ordered GROUP BY src_ip, base_domain
), scored AS (
  SELECT src_ip, base_domain, min(ts) AS first_seen, max(ts) AS last_seen,
         count(*) AS event_count, max(centers.median_delta_s) AS median_delta_s,
         median(abs(ordered.delta_s - centers.median_delta_s)) AS mad_delta_s,
         count(rcode) AS observed_response_count,
         count_if(rcode = 'NXDOMAIN') AS nxdomain_count,
         count_if(rcode = 'NXDOMAIN')::DOUBLE / nullif(count(rcode), 0) AS failure_ratio,
         avg(CASE WHEN sequential_label THEN 1.0 ELSE 0.0 END) AS sequential_ratio,
         epoch(max(ts)) - epoch(min(ts)) AS span_s
  FROM ordered JOIN centers USING (src_ip, base_domain)
  GROUP BY src_ip, base_domain
)
SELECT 'H04' AS hunt_id, src_ip AS entity_key, first_seen, last_seen,
       event_count::BIGINT AS event_count, least(100.0, failure_ratio * 45 + sequential_ratio * 45
         + least(median_delta_s / 7200.0, 1.0) * 10)::DOUBLE AS score,
       'DETECT' AS decision,
       'Sparse, failure-heavy sequential DNS persists with complete collection.' AS reason,
       median_delta_s::DOUBLE AS median_delta_s,
       mad_delta_s::DOUBLE AS mad_delta_s,
       observed_response_count::BIGINT AS observed_response_count,
       nxdomain_count::BIGINT AS nxdomain_count,
       failure_ratio::DOUBLE AS failure_ratio,
       sequential_ratio::DOUBLE AS sequential_ratio,
       span_s::DOUBLE AS span_s,
       'complete' AS analyzed_coverage
FROM scored
WHERE event_count = 36 AND median_delta_s BETWEEN 1020 AND 1380
  AND failure_ratio >= 0.8 AND sequential_ratio >= 0.9;
""",
5: """
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
""",
6: """
WITH ordered AS (
  SELECT src_ip, dst_ip, ts,
         epoch(ts) - epoch(lag(ts) OVER (PARTITION BY src_ip, dst_ip ORDER BY ts)) AS delta_s
  FROM events
  WHERE event_type = 'flow' AND app_proto = 'tls'
    AND coverage_state = 'complete' AND collection_interval = 'present'
), centers AS (
  SELECT src_ip, dst_ip, median(delta_s) AS median_delta_s
  FROM ordered GROUP BY src_ip, dst_ip
), stats AS (
  SELECT src_ip, dst_ip, min(ts) AS first_seen, max(ts) AS last_seen,
         count(*) AS event_count, max(centers.median_delta_s) AS median_delta_s,
         median(abs(ordered.delta_s - centers.median_delta_s)) AS mad_delta_s,
         stddev_pop(delta_s) / nullif(avg(delta_s), 0) AS interval_cv
  FROM ordered JOIN centers USING (src_ip, dst_ip)
  GROUP BY src_ip, dst_ip
)
SELECT 'H06' AS hunt_id, src_ip AS entity_key, first_seen, last_seen,
       event_count::BIGINT AS event_count, greatest(0.0, least(100.0, 100.0 * (1.0 - interval_cv)))::DOUBLE AS score,
       'DETECT' AS decision,
       'Jitter-tolerant recurrence remains stable after coverage checks.' AS reason,
       median_delta_s::DOUBLE AS median_delta_s,
       mad_delta_s::DOUBLE AS mad_delta_s,
       interval_cv::DOUBLE AS interval_cv,
       'complete' AS analyzed_coverage
FROM stats
WHERE event_count >= 12 AND median_delta_s BETWEEN 45 AND 75 AND interval_cv <= 0.25;
""",
7: """
WITH ordered AS (
  SELECT src_ip, dst_ip, ts, bytes_out, bytes_in,
         epoch(ts) - epoch(lag(ts) OVER (PARTITION BY src_ip, dst_ip ORDER BY ts)) AS delta_s
  FROM events
  WHERE event_type = 'flow' AND service = 'tls' AND app_proto = 'tls'
    AND coverage_state = 'complete'
), per_host AS (
  SELECT src_ip, dst_ip, min(ts) AS first_seen, max(ts) AS last_seen,
         count(*) AS observations, median(delta_s) AS median_delta_s,
         coalesce(stddev_pop(delta_s), 0) / nullif(avg(delta_s), 0) AS cadence_cv,
         avg(bytes_out) AS mean_bytes_out, avg(bytes_in) AS mean_bytes_in,
         coalesce(stddev_pop(bytes_out), 0) AS sd_bytes_out,
         coalesce(stddev_pop(bytes_in), 0) AS sd_bytes_in
  FROM ordered GROUP BY src_ip, dst_ip HAVING count(*) >= 8
), cohorts AS (
  SELECT dst_ip, min(first_seen) AS first_seen, max(last_seen) AS last_seen,
         sum(observations) AS event_count, count(*) AS host_count,
         median(median_delta_s) AS cohort_median_delta_s,
         coalesce(stddev_pop(median_delta_s), 0) AS host_cadence_spread_s,
         max(cadence_cv) AS worst_host_cadence_cv,
         avg(mean_bytes_out) AS cohort_mean_bytes_out,
         avg(mean_bytes_in) AS cohort_mean_bytes_in,
         max(sd_bytes_out) AS worst_sd_bytes_out,
         max(sd_bytes_in) AS worst_sd_bytes_in
  FROM per_host GROUP BY dst_ip
)
SELECT 'H07' AS hunt_id, dst_ip AS entity_key, first_seen,
       last_seen, event_count::BIGINT AS event_count,
       least(100.0, host_count * 25.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'A small cross-host cohort shares destination, stable cadence, and stable balanced byte shape.' AS reason,
       host_count::BIGINT AS host_count,
       cohort_median_delta_s::DOUBLE AS cohort_median_delta_s,
       host_cadence_spread_s::DOUBLE AS host_cadence_spread_s,
       worst_host_cadence_cv::DOUBLE AS worst_host_cadence_cv,
       cohort_mean_bytes_out::DOUBLE AS cohort_mean_bytes_out,
       cohort_mean_bytes_in::DOUBLE AS cohort_mean_bytes_in,
       worst_sd_bytes_out::DOUBLE AS worst_sd_bytes_out,
       worst_sd_bytes_in::DOUBLE AS worst_sd_bytes_in
FROM cohorts
WHERE host_count BETWEEN 3 AND 6 AND event_count >= 24
  AND cohort_median_delta_s BETWEEN 290 AND 310
  AND host_cadence_spread_s <= 5 AND worst_host_cadence_cv <= 0.05
  AND cohort_mean_bytes_out BETWEEN 150 AND 300
  AND cohort_mean_bytes_in BETWEEN 150 AND 300
  AND worst_sd_bytes_out <= 5 AND worst_sd_bytes_in <= 5;
""",
8: """
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
""",
9: """
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
""",
10: """
SELECT 'H10' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count, 90.0::DOUBLE AS score,
       'DETECT' AS decision,
       'Lawfully visible outer name and HTTP authority differ without a known proxy rewrite.' AS reason
FROM events
WHERE event_type = 'http' AND visibility_basis = 'lawful-proxy-decryption'
  AND sni IS NOT NULL AND authority IS NOT NULL
  AND lower(sni) <> lower(authority) AND proxy_rewrite = false
GROUP BY src_ip;
""",
11: """
SELECT 'H11' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(coalesce(ts_end, ts)) AS last_seen, count(*)::BIGINT AS event_count,
       88.0::DOUBLE AS score, 'DETECT' AS decision,
       'Established CONNECT session is long-lived, low-throughput, and outside the approved relay path.' AS reason
FROM events
WHERE event_type = 'proxy_session' AND proxy_method = 'CONNECT'
  AND action = 'allow' AND outcome = 'established' AND duration_s >= 3600
  AND (coalesce(bytes_out, 0) + coalesce(bytes_in, 0)) / nullif(duration_s, 0) <= 20
GROUP BY src_ip;
""",
12: """
WITH service_policy (dst_ip, dst_port, transport, expected_protocol) AS (
  VALUES
    ('203.0.113.122', 443, 'tcp', 'tls'),
    ('198.51.100.120', 8080, 'tcp', 'http'),
    ('192.0.2.120', 4443, 'tcp', 'tls')
), observations AS (
  SELECT correlation_key, ts AS event_time_utc, source, src_ip, src_port,
         e.dst_ip, e.dst_port, e.transport, coverage_state, collection_interval,
         coalesce(parser_zeek, parser_suricata) AS detected_protocol,
         p.expected_protocol
  FROM events AS e
  LEFT JOIN service_policy AS p
    ON e.dst_ip = p.dst_ip AND e.dst_port = p.dst_port AND e.transport = p.transport
  WHERE event_type = 'parser_observation'
), paired AS (
  SELECT correlation_key, src_ip, src_port, dst_ip, dst_port, transport,
         expected_protocol, min(event_time_utc) AS first_seen,
         max(event_time_utc) AS last_seen, count(*) AS event_count,
         count(DISTINCT source) AS sensor_count,
         max(CASE WHEN source = 'zeek' THEN detected_protocol END) AS zeek_protocol,
         max(CASE WHEN source = 'suricata' THEN detected_protocol END) AS suricata_protocol,
         bool_and(coverage_state = 'complete') AS coverage_complete
  FROM observations
  GROUP BY correlation_key, src_ip, src_port, dst_ip, dst_port, transport, expected_protocol
)
SELECT 'H12' AS hunt_id, correlation_key AS entity_key, first_seen, last_seen,
       event_count::BIGINT AS event_count, 1.0::DOUBLE AS score,
       CASE WHEN zeek_protocol <> suricata_protocol
         THEN concat('parser_disagreement:zeek=', zeek_protocol,
                     ';suricata=', suricata_protocol, ';packet_truth=required')
         ELSE concat('protocol_policy_mismatch:expected=', expected_protocol,
                     ';observed=', zeek_protocol, ';packet_truth=required') END AS reason
FROM paired
WHERE coverage_complete AND sensor_count >= 2
  AND zeek_protocol IS NOT NULL AND suricata_protocol IS NOT NULL
  AND (zeek_protocol <> suricata_protocol
       OR (zeek_protocol = suricata_protocol AND expected_protocol IS NOT NULL
           AND zeek_protocol <> expected_protocol))
ORDER BY first_seen, entity_key;
""",
13: """
WITH complete_flows AS (
  SELECT *, (bytes_out + bytes_in)::DOUBLE / nullif(duration_s, 0) AS throughput_Bps,
         least(bytes_out, bytes_in)::DOUBLE / nullif(greatest(bytes_out, bytes_in), 0) AS duplex_ratio
  FROM events
  WHERE event_type = 'flow' AND flow_complete = true
    AND connection_state <> 'active-timeout' AND duration_s > 0
), ranked AS (
  SELECT *, count(*) OVER (PARTITION BY service) AS service_cohort_size,
         percent_rank() OVER (PARTITION BY service ORDER BY throughput_Bps) AS throughput_percentile
  FROM complete_flows
)
SELECT 'H13' AS hunt_id, src_ip AS entity_key, ts AS first_seen,
       coalesce(ts_end, ts) AS last_seen, 1::BIGINT AS event_count,
       (70.0 + (1.0 - throughput_percentile) * 16.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Complete TLS flow is persistent, low-throughput, bidirectional, and low in its service cohort.' AS reason,
       duration_s::DOUBLE AS duration_s,
       throughput_Bps::DOUBLE AS throughput_Bps,
       duplex_ratio::DOUBLE AS duplex_ratio,
       service_cohort_size::BIGINT AS service_cohort_size,
       throughput_percentile::DOUBLE AS throughput_percentile
FROM ranked
WHERE service = 'tls' AND duration_s >= 10800 AND throughput_Bps <= 2.0
  AND duplex_ratio >= 0.5 AND throughput_percentile <= 0.2;
""",
14: """
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
""",
15: """
WITH authorized_tunnels (src_role, dst_ip, ip_protocol_number, valid_from, valid_to) AS (
  VALUES ('sdwan_gateway', '198.51.100.150', 47,
          TIMESTAMP '2026-01-01 00:00:00', TIMESTAMP '2027-01-01 00:00:00')
), observations AS (
  SELECT e.*, a.src_role AS authorized_role
  FROM events AS e
  LEFT JOIN authorized_tunnels AS a
    ON e.src_role = a.src_role AND e.dst_ip = a.dst_ip
   AND e.ip_protocol_number = a.ip_protocol_number
   AND e.ts >= a.valid_from AND e.ts < a.valid_to
)
SELECT 'H15' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count, 85.0::DOUBLE AS score,
       'DETECT' AS decision,
       'Observed encapsulation has no effective-dated match in the authorized tunnel inventory.' AS reason,
       min(ip_protocol_number)::BIGINT AS ip_protocol_number,
       min(tunnel_type) AS observed_tunnel_type,
       'no_inventory_match' AS authorization_state
FROM observations
WHERE event_type = 'network_layer' AND ip_protocol_number IN (4, 41, 47)
  AND authorized_role IS NULL AND coverage_state = 'complete' AND action = 'allow'
GROUP BY src_ip;
""",
16: """
WITH approved_services (src_role, dst_ip, dst_port, service, valid_from, valid_to) AS (
  VALUES ('workstation', '198.51.100.160', 22, 'ssh',
          TIMESTAMP '2026-01-01 00:00:00', TIMESTAMP '2027-01-01 00:00:00')
), sessions AS (
  SELECT e.*, a.dst_ip AS approved_destination
  FROM events AS e
  LEFT JOIN approved_services AS a
    ON e.src_role = a.src_role AND e.dst_ip = a.dst_ip AND e.dst_port = a.dst_port
   AND e.service = a.service AND e.ts >= a.valid_from AND e.ts < a.valid_to
)
SELECT 'H16' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(coalesce(ts_end, ts)) AS last_seen, count(*)::BIGINT AS event_count,
       82.0::DOUBLE AS score, 'DETECT' AS decision,
       'Long complete outbound SSH has no effective-dated service-inventory match; forwarding is unproven.' AS reason,
       min(duration_s)::DOUBLE AS minimum_duration_s,
       sum(bytes_out)::BIGINT AS bytes_out,
       sum(bytes_in)::BIGINT AS bytes_in,
       'no_inventory_match' AS authorization_state
FROM sessions
WHERE event_type = 'ssh' AND direction = 'outbound' AND app_proto = 'ssh'
  AND src_role = 'workstation' AND duration_s >= 900 AND flow_complete = true
  AND bytes_out > 0 AND bytes_in > 0 AND action = 'allow' AND approved_destination IS NULL
GROUP BY src_ip;
""",
17: """
SELECT 'H17' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT channel) * 25.0 + count_if(outcome = 'blocked') * 10.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Coherent destination context switches across three channels after blocked attempts.' AS reason
FROM events
WHERE event_type = 'channel_event' AND correlation_key IS NOT NULL
GROUP BY src_ip, dst_ip, correlation_key
HAVING count(DISTINCT channel) >= 3 AND count_if(outcome = 'blocked') >= 2
   AND count_if(outcome = 'established') >= 1
   AND epoch(max(ts)) - epoch(min(ts)) <= 180;
""",
18: """
SELECT 'H18' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT dst_ip) * 3.0 + count(DISTINCT dst_port) * 5.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Workstation shows broad east-west destination and administrative-port fan-out.' AS reason
FROM events
WHERE event_type = 'flow' AND direction = 'east-west'
  AND src_role NOT IN ('vulnerability_scanner', 'load_balancer', 'orchestrator', 'monitoring_server')
GROUP BY src_ip
HAVING count(DISTINCT dst_ip) >= 20 AND count(DISTINCT dst_port) >= 3;
""",
19: """
SELECT 'H19' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT dst_ip) * 15.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Workstation fans out ADMIN$ transfers with service-control RPC metadata; file intent is unknown.' AS reason
FROM events
WHERE event_type = 'smb' AND direction = 'east-west' AND share_name = 'ADMIN$'
  AND rpc_operation = 'svcctl.CreateServiceW' AND src_role = 'workstation'
GROUP BY src_ip HAVING count(DISTINCT dst_ip) >= 5;
""",
20: """
SELECT 'H20' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count, 84.0::DOUBLE AS score,
       'DETECT' AS decision,
       'Peer-to-peer workstation remote administration bypasses the jump-host topology.' AS reason
FROM events
WHERE event_type = 'remote_admin' AND direction = 'east-west'
  AND src_role = 'workstation' AND dst_role = 'workstation'
  AND remote_admin_proto IN ('rdp', 'vnc', 'winrm', 'ssh') AND action = 'allow'
GROUP BY src_ip;
""",
21: """
SELECT 'H21' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT dst_ip) * 6.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Exactly mapped VPN session crosses into high-fan-out administrative east-west traffic.' AS reason
FROM events
WHERE event_type = 'flow' AND src_segment = 'vpn' AND direction = 'east-west'
  AND mapping_state = 'exact' AND vpn_session_id IS NOT NULL
GROUP BY src_ip, vpn_session_id HAVING count(DISTINCT dst_ip) >= 10;
""",
22: """
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
""",
23: """
SELECT 'H23' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(coalesce(ts_end, ts)) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, 60.0 + bytes_out / 1073741824.0 * 5.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Unsampled complete flow shows multi-GiB outbound volume and strong upload asymmetry.' AS reason
FROM events
WHERE event_type = 'flow' AND flow_complete = true AND sample_rate = 1
  AND counter_layer = 'observed_ip' AND bytes_out >= 4294967296
  AND bytes_out::DOUBLE / nullif(bytes_in, 0) >= 10
  AND src_role <> 'backup_server'
GROUP BY src_ip, bytes_out;
""",
24: """
SELECT 'H24' AS hunt_id, src_ip AS entity_key, min(ts) AS first_seen,
       max(ts) AS last_seen, count(*)::BIGINT AS event_count,
       least(100.0, count(DISTINCT CAST(ts AS DATE)) * 6.0 + sum(bytes_out) / 10485760.0)::DOUBLE AS score,
       'DETECT' AS decision,
       'Small outbound chunks accumulate persistently across days with complete collection.' AS reason
FROM events
WHERE event_type = 'flow' AND coverage_state = 'complete'
  AND collection_interval = 'present' AND bytes_out BETWEEN 1048576 AND 10485760
  AND bytes_out::DOUBLE / nullif(bytes_in, 0) >= 10
GROUP BY src_ip
HAVING count(*) >= 28 AND count(DISTINCT CAST(ts AS DATE)) >= 8
   AND sum(bytes_out) >= 83886080;
""",
}

VARCHAR_FIELDS = {
    "event_id", "fixture_id", "case_id", "control", "source", "event_type",
    "sensor", "src_ip", "dst_ip", "transport", "direction", "direction_basis",
    "src_role", "dst_role", "src_segment", "dst_segment", "action", "outcome",
    "connection_state", "service", "app_proto", "channel", "query", "base_domain",
    "qtype", "rcode", "method", "host", "authority", "uri", "user_agent",
    "mime_type", "filename", "file_hash", "sni", "alpn", "tls_version",
    "fingerprint", "cert_subject", "cert_issuer", "ech_status", "quic_version",
    "proxy_method", "policy", "vpn_session_id", "assigned_ip", "route_mode",
    "mapping_state", "counter_layer", "correlation_key", "anomaly", "tunnel_type",
    "share_name", "rpc_operation", "remote_admin_proto", "coverage_state",
    "visibility_basis", "collection_interval", "note",
}
TIMESTAMP_FIELDS = {"ts", "ts_end"}
BOOLEAN_FIELDS = {
    "sequential_label", "cert_self_signed", "sni_cert_match", "flow_complete",
    "parser_zeek", "parser_suricata", "approved", "proxy_rewrite",
}
INTEGER_FIELDS = {
    "src_port", "dst_port", "ip_proto", "answer_count", "dns_label_length",
    "status_code", "cert_valid_days", "packets_out", "packets_in", "sample_rate",
    "icmp_version", "icmp_type", "icmp_code", "payload_len", "icmp_id", "icmp_seq",
    "ip_protocol_number",
}
BIGINT_FIELDS = {"file_size", "bytes_out", "bytes_in"}
DOUBLE_FIELDS = {"dns_label_entropy", "duration_s"}


def schema_type(name: str) -> str:
    if name in TIMESTAMP_FIELDS:
        # Fixture strings are normalized UTC (Z).  TIMESTAMP avoids a runtime
        # timezone-database dependency; the UTC contract is explicit here and
        # in the manifest rather than inferred from the host locale.
        return "TIMESTAMP"
    if name in BOOLEAN_FIELDS:
        # parser fields are protocol strings despite their historical names.
        if name in {"parser_zeek", "parser_suricata"}:
            return "VARCHAR"
        return "BOOLEAN"
    if name in INTEGER_FIELDS:
        return "INTEGER"
    if name in BIGINT_FIELDS:
        return "BIGINT"
    if name in DOUBLE_FIELDS:
        return "DOUBLE"
    if name in VARCHAR_FIELDS:
        return "VARCHAR"
    raise KeyError(name)


def main() -> None:
    # Importing the generator centralizes the field-order contract.
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    from generate_fixtures import FIELDS

    if sorted(QUERIES) != list(range(1, 25)):
        raise RuntimeError("exactly 24 queries are required")
    query_dir = ROOT / "queries"
    schema_dir = ROOT / "schemas"
    query_dir.mkdir(parents=True, exist_ok=True)
    schema_dir.mkdir(parents=True, exist_ok=True)
    for hunt, sql in QUERIES.items():
        header = (
            f"-- Listing B05-H{hunt:02d}-SQL-01\n"
            "-- Engine: DuckDB 1.4.5 LTS\n"
            f"-- Fixture: fixtures/generated/hunt_{hunt:02d}.jsonl\n"
            "-- Input view: events (schemas/canonical_events.sql)\n"
            "-- Ground-truth fields are prohibited from analytic logic.\n"
        )
        (query_dir / f"hunt_{hunt:02d}.sql").write_text(header + sql.strip() + "\n", encoding="utf-8")
    columns = ",\n".join(f"  {name} {schema_type(name)}" for name in FIELDS)
    ddl = (
        "-- Canonical teaching schema v1. Raw producer records remain beside it.\n"
        "-- Nulls mean unavailable unless coverage_state/visibility_basis supplies a narrower reason.\n"
        "CREATE TABLE events (\n" + columns + "\n);\n"
    )
    (schema_dir / "canonical_events.sql").write_text(ddl, encoding="utf-8")
    schema_json = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:practical-threat-hunting:book5:canonical-event:v1",
        "title": "Book 5 canonical network event",
        "type": "object",
        "required": FIELDS,
        "additionalProperties": False,
        "properties": {name: {"type": ["null", "string", "number", "integer", "boolean"]}
                       for name in FIELDS},
        "x-result-columns": RESULT_COLUMNS,
    }
    (schema_dir / "canonical_events.schema.json").write_text(
        json.dumps(schema_json, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
