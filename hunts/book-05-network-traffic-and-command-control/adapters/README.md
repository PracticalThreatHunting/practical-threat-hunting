# Raw-to-canonical adapter contract

Each raw JSONL line carries `fixture_id`, `case_id`, `control`, and `producer`,
followed by `record` (producer-shaped evidence), `adapter_enrichment` (explicit
teaching-only role, policy, interval, or derived inputs), `lineage` (a canonical
field-to-source-path map), and `canonical` (the normalized teaching row). The
answer-key keys exist only for the external test harness. Published queries read
neither the raw envelope nor those keys.

The verifier derives the input-field set from every published SQL listing and
checks every raw row. Each consumed canonical value must resolve exactly through
its declared native record path or its named `adapter_enrichment` path. It also
prohibits ground-truth labels in adapter enrichment. This is a fixture-lineage
assertion, not a claim that synthetic enrichments are universal vendor fields.

`fixture_envelope.sql` exposes raw and canonical views for lineage walkthroughs.
It deliberately does not pretend the embedded canonical struct is a production
vendor adapter. Production onboarding must map a pinned producer schema and
retain the original event alongside the normalized output.

| Producer family | Stable raw evidence used here | Canonical derivation notes |
|---|---|---|
| Zeek JSON | `ts`, `uid`, `id.orig_*`, `id.resp_*`, `proto`, `service`, DNS/HTTP/SSH/file fields, directional bytes | `uid` is retained as correlation evidence. H06 derives canonical `app_proto=tls` from the fixture's pinned service classification; null conn `service` is not overwritten by unrelated logs. H12's SSH classification comes from `ssh.log` joined by `uid`, not from `conn.log.service`. |
| Suricata EVE | tuple, `flow_id`, `event_type`, `app_proto`, TLS/QUIC structs, flow counters | Event-type views are kept separate. H08 fixture TLS includes ALPN, subject/issuer/SAN, validity days, self-signed and name-match evaluations. In production, recompute name/self-sign relationships from the actual certificate chain/SAN rather than trusting a fixture flag. |
| IPFIX teaching JSON | start/end, tuple, protocol IE, directional octets, sample interval, application name/protocol, duration/completion/counter layer | Application fields are explicitly synthetic enrichments, not universal IPFIX IEs. Preserve observation domain/template identity before adapting a real exporter. Do not scale samples unless the exporter semantics support it. |
| Resolver | client/resolver, query/base domain, type/rcode/answers, label statistics, sequence and coverage | Label entropy in H03 is recomputed from query text by SQL. The precomputed raw value is shown only for source comparison. |
| Proxy/SWG | client/server, service/app protocol/channel, SNI/ALPN, HTTP fields, policy/action/visibility, bytes | HTTP authority/path is used only where the fixture marks plaintext or lawful decryption. Policy is an operational allowlist, not ground truth. |
| Firewall | pre-NAT source, destination, transport, action/outcome/state, NAT mapping state, policy, protocol, counters | `mapping_state=ambiguous-nat-collision` prevents H01 attribution. Real adapters must retain both pre/post-NAT tuples and join tolerance. |
| VPN/east-west/packet | tuple, action, session/assignment/mapping/route, byte or ICMP fields (including ICMP identifier and sequence), coverage | VPN identity requires an exact assignment interval; pooled-address ambiguity is not silently assigned. |

Null values remain null. `coverage_state`, `collection_interval`, and
`visibility_basis` narrow some null reasons. They never grant evidence that the
producer did not observe.
