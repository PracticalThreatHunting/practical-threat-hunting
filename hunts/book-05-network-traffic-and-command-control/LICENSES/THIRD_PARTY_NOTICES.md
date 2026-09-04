# Third-party notices and provisional review

This file is an inventory, not legal advice and not a substitute for the full
license texts. No third-party executable, Python wheel, or source distribution
is intentionally vendored in this directory.

| Component | Pinned/tested version | Relationship | Reported license | Release action |
|---|---:|---|---|---|
| CPython | 3.12.13 | External runtime | PSF License 2.0 | Confirm runtime distribution obligations for chosen channel. |
| DuckDB Python | 1.4.5 | Required dependency | MIT | Include the upstream license notice if redistributed. |
| Scapy | 2.6.1 | Required/version-checked dependency; generator does not import it | GPL-2.0-only | Obtain legal review before bundling or distributing; do not assume repository licensing resolves dependency obligations. |
| Zeek | 8.2.2 | Optional external native tool; not bundled | BSD-3-Clause | Preserve upstream notices if later distributed. |
| Suricata | 8.0.6 | Optional external native tool; not bundled | GPL-2.0-only | Obtain legal review before any later bundling or distribution. |
| TShark/Wireshark | 4.6.8 | Optional; NOT_RUN and not bundled | GPL-2.0-or-later (upstream project) | Verify exact package license before bundling; none is planned here. |
| uv | 0.11.33 used for release QA | External environment manager; not bundled | Apache-2.0 OR MIT | Preserve the selected upstream terms if redistributed. |

The dependency lock records package artifact URLs and SHA-256 hashes. License
identifiers above must be rechecked against the exact acquired artifacts before
redistributing any dependency. No reuse license for the first-party Book 5
material is granted; see `NO_PUBLIC_LICENSE.txt`.
