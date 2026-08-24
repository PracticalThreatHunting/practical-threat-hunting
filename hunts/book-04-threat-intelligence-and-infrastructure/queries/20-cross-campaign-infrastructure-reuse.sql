WITH selected_campaign_versions(campaign_id, campaign_version) AS (
    VALUES
      ('CAMPAIGN-GH-JUNE-01', <CAMPAIGN_1_VERSION>),
      ('CAMPAIGN-GH-AUGUST-02', <CAMPAIGN_2_VERSION>)
), approved_campaigns AS (
    SELECT c.campaign_id, c.campaign_version,
           c.observed_start, c.observed_end
    FROM campaign_objects c
    JOIN selected_campaign_versions s
      ON s.campaign_id = c.campaign_id
     AND s.campaign_version = c.campaign_version
    WHERE c.status IN ('approved', 'provisional')
      AND c.cluster_id = 'CLUSTER-LANTERN-27'
      AND c.collected_at < <ANALYSIS_CUTOFF>
), campaign_edges AS (
    SELECT c.campaign_id, c.campaign_version,
           c.observed_start, c.observed_end,
           r.target_node_id, n.node_type AS target_node_type,
           r.relationship_type, r.operational_role,
           r.valid_from, r.valid_until, r.source_id,
           r.source_dependency_id, r.raw_pointer
    FROM approved_campaigns c
    JOIN intel_edges r ON r.source_node_id = c.campaign_id
    JOIN intel_nodes n ON n.node_id = r.target_node_id
    WHERE r.relationship_type IN (
        'used-infrastructure', 'used-capability', 'presented-certificate',
        'used-url-path', 'configured-in-sample'
    )
      AND r.valid_from < c.observed_end
      AND (r.valid_until IS NULL OR r.valid_until > c.observed_start)
      AND r.collected_at < <ANALYSIS_CUTOFF>
      AND n.collected_at < <ANALYSIS_CUTOFF>
), reuse_nodes AS (
    SELECT target_node_id, target_node_type,
           relationship_type, operational_role,
           count(DISTINCT (campaign_id, campaign_version)) AS campaign_version_count,
           array_agg(DISTINCT campaign_id || '@' || campaign_version) AS campaign_versions,
           count(DISTINCT source_dependency_id)
             FILTER (WHERE source_dependency_id IS NOT NULL) AS known_dependency_count,
           bool_or(source_dependency_id IS NULL) AS dependency_unknown,
           min(valid_from) AS first_valid,
           max(valid_until) FILTER (WHERE valid_until IS NOT NULL) AS last_known_valid,
           bool_or(valid_until IS NULL) AS has_open_interval
    FROM campaign_edges
    GROUP BY target_node_id, target_node_type,
             relationship_type, operational_role
    HAVING count(DISTINCT (campaign_id, campaign_version)) >= 2
), prevalence AS (
    SELECT target_node_id, object_type, operational_role,
           count(DISTINCT source_node_id) AS related_node_count,
           count(DISTINCT CASE WHEN source_node_type = 'campaign'
                              THEN source_node_id END) AS all_campaign_count,
           comparison_set_id, snapshot_time
    FROM relationship_prevalence_snapshot
    WHERE snapshot_time = <PREVALENCE_SNAPSHOT_TIME>
      AND snapshot_time < <ANALYSIS_CUTOFF>
      AND comparison_set_id = <COMPARISON_SET_ID>
    GROUP BY target_node_id, object_type, operational_role,
             comparison_set_id, snapshot_time
)
SELECT rn.*, p.related_node_count, p.all_campaign_count,
       p.comparison_set_id, p.snapshot_time
FROM reuse_nodes rn
LEFT JOIN prevalence p
  ON p.target_node_id = rn.target_node_id
 AND p.object_type = rn.target_node_type
 AND p.operational_role = rn.operational_role
 AND p.comparison_set_id = <COMPARISON_SET_ID>
 AND p.snapshot_time = <PREVALENCE_SNAPSHOT_TIME>
ORDER BY rn.campaign_version_count DESC,
         rn.known_dependency_count DESC;
