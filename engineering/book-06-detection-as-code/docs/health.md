# Health contract

Reference health kinds include invalid_event, conflicting_event_id, and enrichment_missing/stale/ambiguous. Enrichment failures route to data-owner. A connected monitor must additionally observe source freshness and volume, mapping rejection, scheduler completion, runtime, materialization, and consumer delivery. Those native monitors were not deployed in this edition. Unknown measurements must not imply health.
