WITH RECURSIVE
seed_nodes AS (
    SELECT node_id,
           ARRAY[node_id] AS node_path,
           ARRAY[]::text[] AS edge_path,
           0 AS depth
    FROM cluster_membership
    WHERE cluster_id = 'CLUSTER-LANTERN-27'
      AND cluster_version = <CLUSTER_VERSION>
      AND membership_status = 'approved'
),
walk AS (
    SELECT node_id, node_path, edge_path, depth
    FROM seed_nodes

    UNION ALL

    SELECT r.target_node_id AS node_id,
           w.node_path || r.target_node_id,
           w.edge_path || r.relationship_id,
           w.depth + 1
    FROM walk w
    JOIN intel_edges r
      ON r.source_node_id = w.node_id
    JOIN expansion_edge_policy p
      ON p.policy_version = <POLICY_VERSION>
     AND p.relationship_type = r.relationship_type
     AND p.action = 'allow'
    LEFT JOIN graph_stop_nodes s
      ON s.node_id = r.target_node_id
     AND s.snapshot_time = <PREVALENCE_SNAPSHOT_TIME>
    WHERE w.depth < 2
      AND s.node_id IS NULL
      AND NOT r.target_node_id = ANY(w.node_path)
      AND (r.valid_until IS NULL OR r.valid_until > <EMERGENCE_WINDOW_START>)
      AND r.valid_from < <EMERGENCE_WINDOW_END>
      AND r.collected_at < <ANALYSIS_CUTOFF>
),
emerging AS (
    SELECT DISTINCT w.node_id, w.node_path, w.edge_path, w.depth
    FROM walk w
    JOIN intel_nodes n ON n.node_id = w.node_id
    WHERE w.depth > 0
      AND n.first_collected_at >= <CLUSTER_CUTOFF_TIME>
      AND n.first_collected_at < <EMERGENCE_WINDOW_END>
      AND n.first_collected_at < <ANALYSIS_CUTOFF>
      AND n.node_type IN ('domain', 'ipv4-addr', 'ipv6-addr', 'url')
      AND NOT EXISTS (
          SELECT 1
          FROM cluster_membership cm
          WHERE cm.cluster_id = 'CLUSTER-LANTERN-27'
            AND cm.node_id = w.node_id
            AND cm.cluster_version = <CLUSTER_VERSION>
      )
)
SELECT e.node_id, e.depth, e.node_path, e.edge_path,
       COUNT(DISTINCT r.source_dependency_id)
         FILTER (WHERE r.source_dependency_id IS NOT NULL) AS known_source_families,
       bool_or(r.source_dependency_id IS NULL) AS source_dependency_unknown,
       COUNT(DISTINCT r.relationship_type) AS relationship_types
FROM emerging e
JOIN intel_edges r
  ON r.relationship_id = ANY(e.edge_path)
GROUP BY e.node_id, e.depth, e.node_path, e.edge_path
ORDER BY e.depth, known_source_families DESC, relationship_types DESC;
