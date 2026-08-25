WITH old_scope AS (
    SELECT n.node_id, n.node_type, n.node_value, n.valid_from, n.valid_until
    FROM intel_nodes n
    WHERE n.cluster_id = 'CLUSTER-LANTERN-27'
      AND (n.valid_until IS NULL OR n.valid_until > <OLD_WINDOW_START>)
      AND n.valid_from < <OLD_WINDOW_END>
      AND n.collected_at < <ANALYSIS_CUTOFF>
), old_traits AS (
    SELECT r.source_node_id AS old_node_id,
           r.relationship_type,
           r.target_node_id AS trait_node_id,
           r.valid_from,
           r.valid_until,
           r.source_id,
           r.source_dependency_id
    FROM intel_edges r
    JOIN old_scope o ON o.node_id = r.source_node_id
    WHERE r.relationship_type IN (
        'presented-certificate',
        'redirected-to',
        'shares-observed-trait',
        'configured-in-sample'
    )
      AND r.valid_from < <OLD_WINDOW_END>
      AND (r.valid_until IS NULL OR r.valid_until > <OLD_WINDOW_START>)
      AND r.collected_at < <ANALYSIS_CUTOFF>
), candidate_new AS (
    SELECT n.node_id, n.node_type, n.node_value,
           n.valid_from, n.valid_until
    FROM intel_nodes n
    WHERE n.valid_from >= <NEW_WINDOW_START>
      AND n.valid_from < <NEW_WINDOW_END>
      AND n.collected_at < <ANALYSIS_CUTOFF>
      AND n.node_id NOT IN (SELECT node_id FROM old_scope)
), shared_traits AS (
    SELECT ot.old_node_id,
           nr.source_node_id AS new_node_id,
           ot.relationship_type,
           ot.trait_node_id,
           ot.source_id AS old_source_id,
           nr.source_id AS new_source_id,
           ot.source_dependency_id AS old_dependency_id,
           nr.source_dependency_id AS new_dependency_id
    FROM old_traits ot
    JOIN intel_edges nr
      ON nr.relationship_type = ot.relationship_type
     AND nr.target_node_id = ot.trait_node_id
    JOIN candidate_new cn ON cn.node_id = nr.source_node_id
    WHERE OVERLAPS_WINDOW(nr.valid_from, nr.valid_until,
                          <NEW_WINDOW_START>, <NEW_WINDOW_END>)
      AND nr.collected_at < <ANALYSIS_CUTOFF>
), internal_transition AS (
    SELECT old_c.asset_id, old_c.process_entity_id,
           old_c.destination_node_id AS old_node_id,
           new_c.destination_node_id AS new_node_id,
           old_c.event_time AS old_contact_time,
           new_c.event_time AS new_contact_time
    FROM enterprise_contacts old_c
    JOIN enterprise_contacts new_c
      ON new_c.asset_id = old_c.asset_id
     AND new_c.process_entity_id = old_c.process_entity_id
     AND new_c.event_time > old_c.event_time
     AND WITHIN_INTERVAL(new_c.event_time, old_c.event_time,
                         <MAX_TRANSITION_INTERVAL>)
    WHERE old_c.destination_node_id IN (SELECT node_id FROM old_scope)
      AND new_c.destination_node_id IN (SELECT node_id FROM candidate_new)
      AND old_c.event_time >= <OLD_WINDOW_START>
      AND old_c.event_time < <OLD_WINDOW_END>
      AND new_c.event_time >= <NEW_WINDOW_START>
      AND new_c.event_time < <NEW_WINDOW_END>
      AND old_c.collected_at < <ANALYSIS_CUTOFF>
      AND new_c.collected_at < <ANALYSIS_CUTOFF>
)
SELECT st.old_node_id, st.new_node_id,
       COUNT(DISTINCT st.relationship_type) AS shared_trait_types,
       COUNT(DISTINCT st.old_dependency_id)
         FILTER (WHERE st.old_dependency_id IS NOT NULL) AS old_known_dependencies,
       COUNT(DISTINCT st.new_dependency_id)
         FILTER (WHERE st.new_dependency_id IS NOT NULL) AS new_known_dependencies,
       bool_or(st.old_dependency_id IS NULL) AS old_dependency_unknown,
       bool_or(st.new_dependency_id IS NULL) AS new_dependency_unknown,
       COUNT(DISTINCT it.asset_id) AS transitioning_assets,
       MIN(it.new_contact_time) AS first_internal_new_contact
FROM shared_traits st
LEFT JOIN internal_transition it
  ON it.old_node_id = st.old_node_id
 AND it.new_node_id = st.new_node_id
GROUP BY st.old_node_id, st.new_node_id;
