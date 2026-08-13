# Query Conventions

The companion repository intentionally separates durable hunt methodology from vendor-specific syntax.

- **KQL:** Microsoft Sentinel / Log Analytics / Defender XDR examples. Table availability differs by product and connector.
- **Splunk SPL:** examples assume normalized or locally mapped fields unless an index/sourcetype is explicitly named.
- **CrowdStrike LogScale:** examples may use normalized placeholder fields; map them to the parser fields in your environment.
- **Sigma:** use as portable detection intent, not proof that backend translations are semantically equivalent.
- **Pseudocode:** provider-neutral logic intended to be reimplemented against local telemetry.

## Validation Rule

Before production use, verify the data source, field semantics, joins, time functions, null handling, aggregation behavior, thresholds, and benign workflows. Test on historical data and, when possible, controlled known-positive events.
