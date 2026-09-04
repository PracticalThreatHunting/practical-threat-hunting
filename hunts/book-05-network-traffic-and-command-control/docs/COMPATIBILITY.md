# Compatibility matrix

| Component | Version | Role | Edition-validation result | Boundary |
|---|---:|---|---|---|
| CPython | 3.12.13 | Canonical runtime | PASS | Verifier requires Python 3.12.x; other minors are unsupported. |
| DuckDB | 1.4.5 | Canonical SQL engine | PASS, all 24 listings | Exact version required because types and aggregates are contract inputs. |
| Scapy package | 2.6.1 | Version-locked companion dependency | PASS version check | Generator deliberately uses a standard-library PCAP writer and does not import Scapy. |
| Zeek | 8.2.2 | Optional native replay | PASS | External Linux x86-64 tool root used for retained evidence; not bundled. |
| Suricata | 8.0.6 | Optional native replay | PASS | External Ubuntu-compatible x86-64 tool root used for retained evidence; not bundled. |
| TShark | 4.6.8 | Optional parser check | NOT_RUN | Binary unavailable; no pass may be inferred. |
| uv | 0.11.33 | Release QA/environment manager | PASS in clean-checkout QA | External tool; earlier/later versions are not part of retained evidence. |
| Linux x86-64 | Current build environment | Full native replay | PASS | Canonical DuckDB tests may work elsewhere with matching CPython wheels; native sensor replay is not claimed elsewhere. |

Without native sensor roots, the supported command reports Zeek, Suricata,
cross-parity, and unavailable TShark checks as `NOT_RUN` while still evaluating
the required deterministic Python/DuckDB suite. This is a declared reduced
environment, not a native-sensor pass.

Known semantic boundaries include the H14 code predicate, H16 byte-counter
label, H17 ordering, and H20 destination-segment artifact documented in
`KNOWN_ARTIFACTS.md`.
