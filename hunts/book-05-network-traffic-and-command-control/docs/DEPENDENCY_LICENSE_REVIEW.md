# Dependency and license review

Review date: 2026-09-03 UTC. Status: published source; external dependencies are not bundled.

## Resolution and integrity

`pyproject.toml` restricts CPython to 3.12 and pins DuckDB 1.4.5 plus Scapy
2.6.1. `uv.lock` fixes distributions and their SHA-256 hashes. Release QA used
uv 0.11.33 with `--frozen --offline`; no dependency was resolved from the
network during the clean-checkout test.

`versions.lock.json` separately records native sensor versions, binary/package
hashes, and the configuration contract. Zeek, Suricata, TShark, CPython, and uv
are external: their binaries are not included in this repository directory.

## License observations

Installed package metadata reports DuckDB as MIT and Scapy as GPL-2.0-only.
The provisional external-tool inventory records CPython under PSF-2.0, Zeek
under BSD-3-Clause, Suricata under GPL-2.0-only, TShark/Wireshark under
GPL-2.0-or-later, and uv under Apache-2.0 OR MIT. The exact acquired artifact and
its complete notice must be reviewed before any bundling or redistribution.

Scapy's pinned presence is deliberate even though the generator does not import
it. The repository's all-rights-reserved status neither grants Scapy rights nor
waives its obligations. Users obtain dependencies directly under their upstream
licenses; no dependency binary is redistributed here.

## Distribution boundary

- Decide whether end users install dependencies themselves or receive any
  bundled artifact; review obligations for that exact model.
- Add all required upstream license texts/notices for anything redistributed.
- Revalidate the CycloneDX SBOM against the final acquisition artifacts.

See `LICENSES/THIRD_PARTY_NOTICES.md` and `docs/SBOM.cdx.json`. This review is
technical inventory, not legal advice.
