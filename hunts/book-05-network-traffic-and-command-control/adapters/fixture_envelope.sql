-- DuckDB 1.4.5. Run from the lab root after fixture generation.
-- This view is for lineage inspection; hunt queries use schemas/canonical_events.sql.
CREATE OR REPLACE VIEW raw_fixture_envelopes AS
SELECT *
FROM read_json_auto(
  'fixtures/generated/raw/hunt_*_raw.jsonl',
  format = 'newline_delimited',
  union_by_name = true,
  maximum_object_size = 1048576
);

CREATE OR REPLACE VIEW raw_zeek AS
SELECT producer, record FROM raw_fixture_envelopes WHERE producer LIKE 'zeek%';

CREATE OR REPLACE VIEW raw_suricata AS
SELECT producer, record FROM raw_fixture_envelopes WHERE producer = 'suricata';

CREATE OR REPLACE VIEW raw_ipfix AS
SELECT producer, record FROM raw_fixture_envelopes WHERE producer = 'ipfix';

CREATE OR REPLACE VIEW raw_resolver AS
SELECT producer, record FROM raw_fixture_envelopes WHERE producer = 'resolver';

CREATE OR REPLACE VIEW raw_proxy AS
SELECT producer, record FROM raw_fixture_envelopes WHERE producer = 'proxy';

CREATE OR REPLACE VIEW raw_firewall AS
SELECT producer, record FROM raw_fixture_envelopes WHERE producer = 'firewall';

CREATE OR REPLACE VIEW canonical_fixture_events AS
SELECT canonical.* FROM raw_fixture_envelopes;
