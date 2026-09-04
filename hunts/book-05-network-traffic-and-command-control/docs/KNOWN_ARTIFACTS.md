# Known artifacts and production extensions

The lab is deterministic teaching evidence, not a drop-in production detector.

- H07 controls intentionally pass the TLS base prefilter. The negative is a
  broad, strongly download-heavy cohort; the edge splits one source across three
  destinations so no pair reaches eight observations.
- H12 canonical rows model a parser/policy discrepancy. Packet replay separately
  proves an SSH-banner session on TCP/443. Zeek classification comes from
  `ssh.log` joined by `uid`; `conn.log` does not supply the service label.
- H14 fixture rows use ICMP code 0 and now preserve identifier and sequence in
  the native packet record. The SQL does not filter `icmp_code`; add `= 0` for a
  production echo-only interpretation.
- H16 raw Zeek `orig_bytes`/`resp_bytes` are payload estimates. Ignore the unused
  canonical `counter_layer='observed_ip'` generator default and document actual
  exporter/log counter layers in production.
- H17 fixture timestamps encode an order, but SQL tests only the bounded
  multichannel group. Add explicit ordered-event logic before claiming a causal
  DNS-to-web-to-QUIC sequence.
- H20 private destination addresses carry the default
  `dst_segment='internet'`. The query does not use that field; production logic
  must derive direction/segments from an effective-dated network inventory.
- Scapy 2.6.1 is pinned and checked, but deterministic PCAP generation uses only
  the Python standard library to avoid interface discovery and opens no socket.
- Inline service, role, and authorization inventories are intentionally small.
  Replace them with governed effective-dated sources and re-baseline every
  threshold before operational use.

The exhaustive raw-lineage check distinguishes native producer paths from
explicit `adapter_enrichment`. An enrichment is declared evidence provenance,
not a claim that a vendor emits that field.
