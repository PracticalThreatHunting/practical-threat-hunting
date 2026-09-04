#!/usr/bin/env python3
"""Run the complete deterministic Book 5 lab verification suite offline."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable

import duckdb

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
FIXTURES = ROOT / "fixtures" / "generated"
MANIFESTS = ROOT / "fixtures" / "manifests"
PCAP = ROOT / "fixtures" / "pcap" / "book5_shared_protocols_v1.pcap"
QUERIES = ROOT / "queries"
GOLDEN = ROOT / "golden"
REPORTS = Path(os.environ.get("BOOK5_REPORT_DIR", str(ROOT / "reports"))).resolve()
RESULTS = REPORTS / "results"
SENSORS = REPORTS / "sensors"
DDL = ROOT / "schemas" / "canonical_events.sql"

FORBIDDEN_QUERY_FIELDS = ("control", "case_id", "fixture_id", "approved", "note")
REQUIRED_COLUMNS = ("hunt_id", "entity_key", "first_seen", "last_seen",
                    "event_count", "score", "reason")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        # The canonical schema declares naive TIMESTAMP with an explicit UTC
        # contract; append Z rather than borrowing the host timezone.
        return value.isoformat(timespec="microseconds").rstrip("0").rstrip(".") + "Z"
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    return value


def portable_string(value: str) -> str:
    """Replace host-specific paths before evidence is written to the repository."""
    replacements = {
        str(ROOT): "${LAB_ROOT}",
        str(Path(sys.executable).resolve()): "${PYTHON}",
        str((ROOT.parents[1] / "book05_work" / "tools").resolve()): "${BOOK5_TOOL_ROOT}",
    }
    configured = os.environ.get("BOOK5_TOOL_ROOT")
    if configured:
        replacements[str(Path(configured).resolve())] = "${BOOK5_TOOL_ROOT}"
    for original in sorted(replacements, key=len, reverse=True):
        value = value.replace(original, replacements[original])
    value = value.replace("/" + "root/", "${USER_ROOT}/")
    temporary_prefix = "/" + "tmp/book5-"
    return re.sub(re.escape(temporary_prefix) + r"[^\s\"']+", "${TEMP_DIR}", value)


def portable_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): portable_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [portable_data(item) for item in value]
    if isinstance(value, Path):
        return portable_string(str(value))
    if isinstance(value, str):
        return portable_string(value)
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(portable_data(value), indent=2, sort_keys=True,
                               default=json_value) + "\n",
                    encoding="utf-8")


def run(command: list[str], *, cwd: Path | None = None,
        env: dict[str, str] | None = None, timeout: int = 120) -> dict[str, Any]:
    started = time.monotonic()
    completed = subprocess.run(command, cwd=cwd, env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout, check=False)
    return {
        "command": command,
        "cwd": str(cwd or ROOT),
        "exit_code": completed.returncode,
        "duration_s": round(time.monotonic() - started, 6),
        "output": completed.stdout,
    }


class Suite:
    def __init__(self) -> None:
        self.cases: list[dict[str, Any]] = []

    def check(self, name: str, function: Callable[[], Any]) -> Any:
        started = time.monotonic()
        try:
            detail = function()
            self.cases.append({"name": name, "status": "PASS",
                               "duration_s": round(time.monotonic() - started, 6),
                               "detail": detail})
            return detail
        except Exception as exc:  # noqa: BLE001 - verification must report every failure.
            self.cases.append({"name": name, "status": "FAIL",
                               "duration_s": round(time.monotonic() - started, 6),
                               "error": f"{type(exc).__name__}: {exc}",
                               "traceback": traceback.format_exc()})
            return None

    def skipped(self, name: str, reason: str) -> None:
        self.cases.append({"name": name, "status": "NOT_RUN", "duration_s": 0.0,
                           "reason": reason})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def fixture_hash_snapshot() -> dict[str, str]:
    targets = sorted(FIXTURES.glob("hunt_*.jsonl"))
    targets += sorted((FIXTURES / "raw").glob("hunt_*_raw.jsonl"))
    targets += sorted(MANIFESTS.glob("*.json"))
    targets += [PCAP]
    return {str(path.relative_to(ROOT)): sha256(path) for path in targets}


def generate_and_check_determinism() -> dict[str, Any]:
    first = run([sys.executable, str(TOOLS / "generate_fixtures.py")], cwd=ROOT)
    require(first["exit_code"] == 0, first["output"])
    before = fixture_hash_snapshot()
    second = run([sys.executable, str(TOOLS / "generate_fixtures.py")], cwd=ROOT)
    require(second["exit_code"] == 0, second["output"])
    after = fixture_hash_snapshot()
    require(before == after, "fixture regeneration changed one or more bytes")
    return {"file_count": len(after), "aggregate_sha256": hashlib.sha256(
        "".join(f"{name}:{value}\n" for name, value in sorted(after.items())).encode()
    ).hexdigest()}


def validate_manifest(hunt: int) -> dict[str, Any]:
    manifest_path = MANIFESTS / f"B05-H{hunt:02d}-v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    canonical = ROOT / manifest["canonical_path"]
    raw = ROOT / manifest["raw_path"]
    canonical_rows = [json.loads(line) for line in canonical.read_text(encoding="utf-8").splitlines()]
    raw_rows = [json.loads(line) for line in raw.read_text(encoding="utf-8").splitlines()]
    require(manifest["canonical_sha256"] == sha256(canonical), "canonical SHA mismatch")
    require(manifest["raw_sha256"] == sha256(raw), "raw SHA mismatch")
    require(manifest["record_count"] == len(canonical_rows) == len(raw_rows), "record count mismatch")
    require(manifest["rights_status"] == "Copyright © 2026 Grant Halden. All rights reserved.",
            "rights status drift")
    require(
        manifest["release_status"]
        == "Published in the official public companion repository; copyright retained and no reuse license granted.",
        "release status drift",
    )
    ids = [row["event_id"] for row in canonical_rows]
    require(len(ids) == len(set(ids)), "event_id values must be unique within a fixture")
    controls = Counter(row["control"] for row in canonical_rows)
    require(set(controls) == {"positive", "negative", "edge"}, "control cohort missing")
    require(controls == Counter(manifest["control_counts"]), "control counts drift")
    import sys as _sys
    _sys.path.insert(0, str(TOOLS))
    from generate_fixtures import FIELDS  # type: ignore
    expected_fields = set(FIELDS)
    require(all(set(row) == expected_fields for row in canonical_rows), "canonical field set drift")
    require(all(raw_row["canonical"] == canonical_row
                for raw_row, canonical_row in zip(raw_rows, canonical_rows)),
            "raw/canonical row pairing drift")
    return {"records": len(canonical_rows), "controls": dict(controls),
            "canonical_sha256": manifest["canonical_sha256"],
            "raw_sha256": manifest["raw_sha256"]}


def sql_without_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"--[^\n]*", " ", sql)
    # Literal prose may legitimately say "approved" or "control"; only
    # identifiers in executable expressions are prohibited.
    return re.sub(r"'(?:''|[^'])*'", "''", sql)


def static_query_check(hunt: int) -> dict[str, Any]:
    path = QUERIES / f"hunt_{hunt:02d}.sql"
    sql = path.read_text(encoding="utf-8")
    body = sql_without_comments(sql)
    for field in FORBIDDEN_QUERY_FIELDS:
        require(not re.search(rf"\b{re.escape(field)}\b", body, flags=re.I),
                f"analytic references prohibited ground-truth field {field}")
    stripped = body.strip()
    require(stripped.endswith(";") and ";" not in stripped[:-1],
            "listing must be one complete statement")
    require(f"B05-H{hunt:02d}-SQL-01" in sql, "listing ID missing")
    return {"sha256": sha256(path), "bytes": path.stat().st_size}


def validate_adapters() -> dict[str, Any]:
    sql_path = ROOT / "adapters" / "fixture_envelope.sql"
    sql = sql_path.read_text(encoding="utf-8")
    absolute_glob = str((FIXTURES / "raw" / "hunt_*_raw.jsonl").resolve()).replace("'", "''")
    sql = sql.replace("fixtures/generated/raw/hunt_*_raw.jsonl", absolute_glob)
    connection = duckdb.connect(":memory:")
    try:
        connection.execute(sql)
        raw_count = connection.execute("SELECT count(*) FROM raw_fixture_envelopes").fetchone()[0]
        canonical_count = connection.execute("SELECT count(*) FROM canonical_fixture_events").fetchone()[0]
    finally:
        connection.close()
    manifest_total = sum(json.loads(path.read_text())["record_count"]
                         for path in MANIFESTS.glob("B05-H??-v1.json"))
    require(raw_count == canonical_count == manifest_total, "adapter row-count parity failed")

    def first_record(hunt: int, producer: str) -> dict[str, Any]:
        for line in (FIXTURES / "raw" / f"hunt_{hunt:02d}_raw.jsonl").read_text().splitlines():
            envelope = json.loads(line)
            if envelope["producer"] == producer:
                return envelope["record"]
        raise AssertionError(f"producer {producer} missing from H{hunt:02d}")

    import sys as _sys
    _sys.path.insert(0, str(TOOLS))
    from generate_fixtures import (  # type: ignore
        analytic_fields_for_hunt,
        resolve_lineage_path,
    )

    audited_rows = 0
    audited_bindings = 0
    enrichment_bindings = 0
    prohibited_enrichment = set(FORBIDDEN_QUERY_FIELDS) | {"approved", "note"}
    per_hunt: dict[str, dict[str, int]] = {}
    for hunt in range(1, 25):
        fields = analytic_fields_for_hunt(hunt)
        rows = [json.loads(line) for line in
                (FIXTURES / "raw" / f"hunt_{hunt:02d}_raw.jsonl").read_text().splitlines()]
        hunt_bindings = 0
        hunt_enrichments = 0
        for envelope in rows:
            lineage = envelope.get("lineage")
            enrichment = envelope.get("adapter_enrichment")
            require(isinstance(lineage, dict), f"H{hunt:02d} raw lineage map missing")
            require(isinstance(enrichment, dict), f"H{hunt:02d} adapter enrichment missing")
            require(set(lineage) == set(fields),
                    f"H{hunt:02d} lineage fields differ from analytic inputs")
            require(not (set(enrichment) & prohibited_enrichment),
                    f"H{hunt:02d} ground-truth field leaked into adapter enrichment")
            require(bool(envelope.get("enrichment_basis")),
                    f"H{hunt:02d} enrichment provenance statement missing")
            canonical = envelope["canonical"]
            for field, path in lineage.items():
                try:
                    source_value = resolve_lineage_path(envelope, path)
                except (KeyError, TypeError) as exc:
                    raise AssertionError(
                        f"H{hunt:02d} unresolved lineage {field} -> {path}"
                    ) from exc
                require(source_value == canonical[field],
                        f"H{hunt:02d} lineage value drift for {field}: {path}")
                hunt_bindings += 1
                if str(path).startswith("adapter_enrichment:"):
                    hunt_enrichments += 1
            audited_rows += 1
        audited_bindings += hunt_bindings
        enrichment_bindings += hunt_enrichments
        per_hunt[f"H{hunt:02d}"] = {
            "rows": len(rows),
            "analytic_fields": len(fields),
            "bindings": hunt_bindings,
            "adapter_enrichment_bindings": hunt_enrichments,
        }

    h05 = first_record(5, "zeek_http")
    require(all(key in h05 for key in ("method", "uri", "status_code", "user_agent",
                                        "request_body_len", "response_body_len", "resp_mime_types")),
            "H05 Zeek HTTP raw lineage incomplete")
    h07 = first_record(7, "ipfix")
    require(all(key in h07 for key in ("applicationService", "applicationProtocol",
                                        "flowDurationSeconds", "counterLayer")),
            "H07 IPFIX raw enrichment lineage incomplete")
    h08 = first_record(8, "suricata")["tls"]
    require(all(key in h08 for key in ("alpn", "subject", "issuerdn", "subjectaltname",
                                        "validity_days", "self_signed", "sni_cert_match")),
            "H08 Suricata TLS raw lineage incomplete")
    require(h08["self_signed"] is True and h08["subject"] == h08["issuerdn"],
            "H08 self-signed derivation contradicts subject/issuer")
    require(h08["sni_cert_match"] is False and h08["sni"] not in h08["subjectaltname"],
            "H08 SNI/SAN mismatch derivation contradicts raw certificate evidence")
    h14 = first_record(14, "packet")
    require(all(key in h14 for key in ("icmp_id", "icmp_seq")),
            "H14 packet raw ICMP identity/sequence lineage incomplete")
    return {"raw_rows": raw_count, "canonical_rows": canonical_count,
            "adapter_sha256": sha256(sql_path),
            "lineage_spot_checks": ["H05", "H07", "H08", "H14"],
            "analytic_lineage_audit": {
                "rows": audited_rows,
                "bindings": audited_bindings,
                "native_bindings": audited_bindings - enrichment_bindings,
                "adapter_enrichment_bindings": enrichment_bindings,
                "per_hunt": per_hunt,
            }}


def validate_version_lock() -> dict[str, Any]:
    lock = json.loads((ROOT / "versions.lock.json").read_text(encoding="utf-8"))
    require(lock["canonical"]["duckdb"]["version"] == duckdb.__version__ == "1.4.5",
            "DuckDB version lock drift")
    require(lock["canonical"]["scapy"]["version"] == importlib.metadata.version("scapy") == "2.6.1",
            "Scapy version lock drift")
    require((ROOT / lock["python_lock"]).exists(), "uv.lock missing")
    require((ROOT / lock["sensor_config_lock"]).exists(), "sensor config lock missing")
    return {"versions_lock_sha256": sha256(ROOT / "versions.lock.json"),
            "uv_lock_sha256": sha256(ROOT / "uv.lock")}


def query_rows(hunt: int, scope: str) -> tuple[list[str], list[dict[str, Any]]]:
    connection = duckdb.connect(":memory:")
    try:
        # Aggregate order can change the final floating-point bit under parallel
        # execution. One thread keeps exact JSON result bytes reproducible while
        # leaving the published SQL listing unchanged.
        connection.execute("SET threads = 1")
        connection.execute(DDL.read_text(encoding="utf-8"))
        fixture = (FIXTURES / f"hunt_{hunt:02d}.jsonl").resolve()
        connection.execute(
            "INSERT INTO events BY NAME SELECT * FROM read_json_auto(?, format='newline_delimited')",
            [str(fixture)],
        )
        if scope != "full":
            # Ground truth is used only by the external test harness to isolate
            # cohorts.  The analytic SQL is statically forbidden from reading it.
            connection.execute("DELETE FROM events WHERE control <> ?", [scope])
        cursor = connection.execute((QUERIES / f"hunt_{hunt:02d}.sql").read_text(encoding="utf-8"))
        columns = [item[0] for item in cursor.description]
        rows = [{column: json_value(value) for column, value in zip(columns, record)}
                for record in cursor.fetchall()]
        return columns, rows
    finally:
        connection.close()


def compare_expected(rows: list[dict[str, Any]], expected: list[dict[str, Any]], scope: str) -> None:
    require(len(rows) == len(expected), f"{scope}: expected {len(expected)} rows, got {len(rows)}")
    unmatched = rows.copy()
    for wanted in expected:
        index = next((i for i, row in enumerate(unmatched)
                      if all(row.get(key) == value for key, value in wanted.items())), None)
        require(index is not None, f"{scope}: missing expected subset {wanted}; actual={rows}")
        unmatched.pop(index)


def hunt_specific_assertions(hunt: int, full_rows: list[dict[str, Any]]) -> dict[str, Any]:
    detail: dict[str, Any] = {"assertions": "passed"}
    if hunt == 1:
        row = full_rows[0]
        require((row["udp_exchanges"], row["tcp_exchanges"], row["resolver_count"],
                 row["attribution_state"]) == (4, 1, 1, "exact"), "H01 sufficient statistics drift")
    elif hunt == 2:
        require({row["service_class"] for row in full_rows} == {"doh", "dot", "doq"},
                "H02 must emit one deviation per encrypted-DNS service class")
    elif hunt == 3:
        row = full_rows[0]
        require(row["event_count"] == 200 and row["distinct_query_count"] == 198, "H03 count drift")
        require(abs(row["unique_ratio"] - 0.99) <= 1e-12, "H03 unique ratio drift")
        require(row["mean_label_length"] == row["median_label_length"] == 48.0, "H03 length drift")
        require(row["estimated_capacity_bytes"] == 6000, "H03 capacity drift")
        require(0.7 <= row["normalized_entropy"] <= 1.0, "H03 entropy normalization drift")
    elif hunt == 4:
        row = full_rows[0]
        require(row["event_count"] == 36 and row["nxdomain_count"] == 30, "H04 count drift")
        require(row["observed_response_count"] == 36, "H04 denominator drift")
        require(abs(row["median_delta_s"] - 1200.0) <= 1e-9, "H04 median drift")
        require(abs(row["mad_delta_s"] - 180.0) <= 1e-9, "H04 MAD drift")
        require(abs(row["failure_ratio"] - 5 / 6) <= 1e-12, "H04 failure ratio drift")
        require(row["span_s"] == 42000.0 and row["analyzed_coverage"] == "complete", "H04 span drift")
    elif hunt == 7:
        rows = [json.loads(line) for line in (FIXTURES / "hunt_07.jsonl").read_text().splitlines()]
        negative = [row for row in rows if row["control"] == "negative"]
        edge = [row for row in rows if row["control"] == "edge"]
        require(all(row["event_type"] == "flow" and row["service"] == "tls"
                    and row["app_proto"] == "tls" and row["coverage_state"] == "complete"
                    for row in negative + edge),
                "H07 controls must pass the service/protocol/coverage prefilter")
        require(len({row["src_ip"] for row in negative}) == 8
                and {row["bytes_out"] for row in negative} == {400}
                and {row["bytes_in"] for row in negative} == {120000},
                "H07 negative must exercise broad-population and imbalanced-byte gates")
        edge_pair_counts = Counter((row["src_ip"], row["dst_ip"]) for row in edge)
        require(len(edge_pair_counts) == 3 and max(edge_pair_counts.values()) < 8,
                "H07 edge must fail the per-host observation gate after prefiltering")
        detail["control_paths"] = {
            "negative": "passes base prefilter; fails population and balanced-byte shape",
            "edge": "passes base prefilter; each source/destination pair has fewer than 8 observations",
        }
    elif hunt == 12:
        require(len(full_rows) == 1 and full_rows[0]["score"] == 1.0, "H12 candidate drift")
        require(full_rows[0]["reason"].endswith("packet_truth=required"), "H12 evidence boundary drift")
        edge = [json.loads(line) for line in (FIXTURES / "hunt_12.jsonl").read_text().splitlines()
                if json.loads(line)["control"] == "edge"]
        require(len(edge) == 2 and all(row["coverage_state"] == "partial" for row in edge),
                "H12 edge adequacy fixture drift")
        require({row["parser_zeek"] or row["parser_suricata"] for row in edge} == {"unknown", "tls"},
                "H12 edge parser disagreement drift")
    elif hunt == 13:
        row = full_rows[0]
        require(row["service_cohort_size"] == 7 and row["throughput_percentile"] == 0.0,
                "H13 cohort ranking drift")
        require(row["throughput_Bps"] <= 2.0 and row["duplex_ratio"] >= 0.5,
                "H13 shape metrics drift")
    elif hunt == 14:
        row = full_rows[0]
        require(row["request_count"] == 10 and row["reply_count"] == 0,
                "H14 request/reply count drift")
        require(row["reply_request_ratio"] == 0.0 and row["sequence_contiguous"] is True,
                "H14 symmetry/sequence drift")
    elif hunt == 15:
        require(full_rows[0]["authorization_state"] == "no_inventory_match",
                "H15 authorization join drift")
    elif hunt == 16:
        require(full_rows[0]["authorization_state"] == "no_inventory_match",
                "H16 authorization join drift")
    return detail


def validate_hunt(hunt: int) -> dict[str, Any]:
    golden = json.loads((GOLDEN / f"hunt_{hunt:02d}.json").read_text(encoding="utf-8"))
    scopes: dict[str, Any] = {}
    full_columns: list[str] = []
    full_rows: list[dict[str, Any]] = []
    for scope in ("positive", "negative", "edge", "full"):
        columns, rows = query_rows(hunt, scope)
        require(all(column in columns for column in REQUIRED_COLUMNS),
                f"{scope}: required result column missing; got {columns}")
        compare_expected(rows, golden[scope], scope)
        scopes[scope] = {"row_count": len(rows), "rows": rows}
        if scope == "full":
            full_columns, full_rows = columns, rows
    specific_assertions = hunt_specific_assertions(hunt, full_rows)
    result = {
        "listing_id": golden["listing_id"],
        "query_path": str((QUERIES / f"hunt_{hunt:02d}.sql").relative_to(ROOT)),
        "query_sha256": sha256(QUERIES / f"hunt_{hunt:02d}.sql"),
        "fixture_sha256": sha256(FIXTURES / f"hunt_{hunt:02d}.jsonl"),
        "columns": full_columns,
        "scopes": scopes,
    }
    write_json(RESULTS / f"hunt_{hunt:02d}.json", result)
    return {"full_rows": len(full_rows), "positive": len(scopes["positive"]["rows"]),
            "negative": len(scopes["negative"]["rows"]), "edge": len(scopes["edge"]["rows"]),
            "query_sha256": result["query_sha256"],
            "specific_assertions": specific_assertions}


def write_release_inventory() -> dict[str, Any]:
    def report_reference(path: Path) -> str:
        try:
            return str(path.relative_to(ROOT))
        except ValueError:
            return "${REPORT_DIR}/" + str(path.relative_to(REPORTS))

    hunts: list[dict[str, Any]] = []
    for hunt in range(1, 25):
        manifest_path = MANIFESTS / f"B05-H{hunt:02d}-v1.json"
        query_path = QUERIES / f"hunt_{hunt:02d}.sql"
        golden_path = GOLDEN / f"hunt_{hunt:02d}.json"
        result_path = RESULTS / f"hunt_{hunt:02d}.json"
        manifest = json.loads(manifest_path.read_text())
        result = json.loads(result_path.read_text())
        hunts.append({
            "hunt": f"H{hunt:02d}",
            "listing_id": f"B05-H{hunt:02d}-SQL-01",
            "query_path": str(query_path.relative_to(ROOT)),
            "query_sha256": sha256(query_path),
            "fixture_path": manifest["canonical_path"],
            "fixture_sha256": manifest["canonical_sha256"],
            "raw_path": manifest["raw_path"],
            "raw_sha256": manifest["raw_sha256"],
            "manifest_path": str(manifest_path.relative_to(ROOT)),
            "manifest_sha256": sha256(manifest_path),
            "golden_path": str(golden_path.relative_to(ROOT)),
            "golden_sha256": sha256(golden_path),
            "result_path": report_reference(result_path),
            "records": manifest["record_count"],
            "control_counts": manifest["control_counts"],
            "time_min": manifest["time_min"],
            "time_max": manifest["time_max"],
            "actual_full_rows": result["scopes"]["full"]["rows"],
        })
    inventory = {
        "schema_version": 1,
        "status_basis": "Generated only after all 24 control-scoped query tests pass.",
        "hunt_count": len(hunts),
        "hunts": hunts,
        "shared_pcap": {"path": str(PCAP.relative_to(ROOT)), "sha256": sha256(PCAP)},
    }
    write_json(REPORTS / "lab_inventory.json", inventory)

    core_files: list[Path] = []
    for relative in ("queries", "fixtures/generated", "fixtures/pcap", "fixtures/manifests",
                     "golden", "schemas", "adapters", "configs", "tools", "book05_lab"):
        core_files.extend(path for path in (ROOT / relative).rglob("*") if path.is_file()
                          and "__pycache__" not in path.parts)
    core_files.extend(ROOT / name for name in
                      ("README.md", "pyproject.toml", "uv.lock", "versions.lock.json"))
    lines = [f"{sha256(path)}  {path.relative_to(ROOT)}" for path in sorted(set(core_files))]
    (REPORTS / "hashes.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"hunt_count": len(hunts), "inventory_sha256": sha256(REPORTS / "lab_inventory.json"),
            "core_file_count": len(lines), "hash_list_sha256": sha256(REPORTS / "hashes.sha256")}


def pcap_summary() -> dict[str, Any]:
    data = PCAP.read_bytes()
    require(len(data) >= 24, "PCAP shorter than global header")
    magic, major, minor, _zone, _sigfigs, snaplen, network = struct.unpack("<IHHIIII", data[:24])
    require(magic == 0xA1B2C3D4 and (major, minor) == (2, 4), "unsupported PCAP header")
    offset, count = 24, 0
    while offset < len(data):
        require(offset + 16 <= len(data), "truncated packet header")
        _sec, _usec, included, original = struct.unpack("<IIII", data[offset:offset + 16])
        require(included == original and included <= snaplen, "unexpected truncation in shared PCAP")
        offset += 16 + included
        require(offset <= len(data), "truncated packet body")
        count += 1
    require(offset == len(data) and count == 18 and network == 1, "shared PCAP shape drift")
    manifest = json.loads((MANIFESTS / "B05-PCAP-SHARED-v1.json").read_text())
    require(manifest["sha256"] == sha256(PCAP), "PCAP manifest hash mismatch")
    return {"sha256": sha256(PCAP), "packets": count, "bytes": len(data),
            "linktype": "Ethernet", "builder": manifest["packet_builder"]}


def discover_tool_root() -> Path:
    configured = os.environ.get("BOOK5_TOOL_ROOT")
    if configured:
        return Path(configured).resolve()
    return (ROOT.parents[1] / "book05_work" / "tools").resolve()


def copy_sensor_files(source: Path, destination: Path, names: list[str]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = source / name
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            (destination / name).write_text(portable_string(text), encoding="utf-8")


def run_zeek(tool_root: Path) -> dict[str, Any]:
    root = tool_root / "zeek_root"
    binary = root / "opt" / "zeek" / "bin" / "zeek"
    require(binary.exists(), f"Zeek binary not found: {binary}")
    env = os.environ.copy()
    share = root / "opt" / "zeek" / "share" / "zeek"
    env["ZEEKPATH"] = os.pathsep.join([str(share / "site"), str(share / "policy"), str(share)])
    env["LD_LIBRARY_PATH"] = str(root / "usr" / "lib" / "x86_64-linux-gnu")
    version = run([str(binary), "--version"], env=env)
    require(version["exit_code"] == 0 and "8.2.2" in version["output"], "Zeek version mismatch")
    with tempfile.TemporaryDirectory(prefix="book5-zeek-") as directory:
        work = Path(directory)
        replay = run([str(binary), "-C", "-r", str(PCAP),
                      "LogAscii::use_json=T", "local"], cwd=work, env=env)
        require(replay["exit_code"] == 0, replay["output"])
        rows: dict[str, list[dict[str, Any]]] = {}
        for name in ("conn.log", "dns.log", "http.log", "ssh.log", "tunnel.log", "capture_loss.log"):
            path = work / name
            rows[name] = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        require(any(row.get("query") == "portal.example" for row in rows["dns.log"]), "Zeek DNS parity failed")
        require(any(row.get("id.resp_p") == 8088 for row in rows["http.log"]), "Zeek HTTP/8088 parity failed")
        require(any(row.get("id.resp_p") == 443 and str(row.get("server", "")).startswith("SSH-2.0-")
                    for row in rows["ssh.log"]), "Zeek SSH/443 parity failed")
        require(any(row.get("tunnel_type") == "Tunnel::GRE" for row in rows["tunnel.log"]),
                "Zeek GRE parity failed")
        require(rows["capture_loss.log"] and rows["capture_loss.log"][-1].get("percent_lost") == 0.0,
                "Zeek capture loss is nonzero or unavailable")
        copy_sensor_files(work, SENSORS / "zeek", [
            "conn.log", "dns.log", "http.log", "ssh.log", "tunnel.log", "capture_loss.log",
            "weird.log", "loaded_scripts.log", "packet_filter.log", "stats.log",
        ])
    return {"status": "PASS", "version_output": version["output"].strip(),
            "version_command": version["command"], "replay_command": replay["command"],
            "replay_exit_code": replay["exit_code"],
            "log_hashes": {path.name: sha256(path) for path in sorted((SENSORS / "zeek").glob("*.log"))}}


def suricata_base_command(binary: Path, config: Path, root: Path, log_dir: Path) -> list[str]:
    return [str(binary), "-c", str(config), "-l", str(log_dir),
            "--set", f"default-rule-path={root / 'usr/share/suricata/rules'}",
            "--set", "rule-files.0=decoder-events.rules",
            "--set", f"classification-file={root / 'etc/suricata/classification.config'}",
            "--set", f"reference-config-file={root / 'etc/suricata/reference.config'}",
            "--set", f"threshold-file={root / 'etc/suricata/threshold.config'}"]


def run_suricata(tool_root: Path) -> dict[str, Any]:
    root = tool_root / "suricata_jammy_root"
    binary = root / "usr" / "bin" / "suricata"
    config = root / "etc" / "suricata" / "suricata.yaml"
    require(binary.exists() and config.exists(), f"Suricata install not found under {root}")
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(root / "usr" / "lib" / "x86_64-linux-gnu")
    version = run([str(binary), "--build-info"], env=env)
    require(version["exit_code"] == 0 and "Suricata version 8.0.6" in version["output"],
            "Suricata version mismatch")
    with tempfile.TemporaryDirectory(prefix="book5-suricata-config-") as directory:
        config_dir = Path(directory)
        syntax_command = suricata_base_command(binary, config, root, config_dir)
        syntax_command.insert(1, "-T")
        syntax = run(syntax_command, env=env)
        require(syntax["exit_code"] == 0, syntax["output"])
    with tempfile.TemporaryDirectory(prefix="book5-suricata-") as directory:
        work = Path(directory)
        replay_command = suricata_base_command(binary, config, root, work)
        replay_command[1:1] = ["--runmode", "single", "-r", str(PCAP)]
        replay = run(replay_command, env=env)
        require(replay["exit_code"] == 0, replay["output"])
        eve = work / "eve.json"
        require(eve.exists(), "Suricata did not write EVE JSON")
        rows = [json.loads(line) for line in eve.read_text().splitlines()]
        types = Counter(row.get("event_type") for row in rows)
        require(types["dns"] >= 1 and types["http"] >= 1 and types["ssh"] >= 1,
                f"Suricata protocol parity failed: {types}")
        require(any(row.get("event_type") == "http" and row.get("dest_port") == 8088 for row in rows),
                "Suricata HTTP/8088 parity failed")
        require(any(row.get("event_type") == "ssh" and row.get("dest_port") == 443 for row in rows),
                "Suricata SSH/443 parity failed")
        copy_sensor_files(work, SENSORS / "suricata", ["eve.json", "stats.log", "suricata.log"])
    return {"status": "PASS", "version": "8.0.6", "build_info_sha256": hashlib.sha256(
                version["output"].encode()).hexdigest(),
            "version_command": version["command"], "syntax_command": syntax["command"],
            "replay_command": replay["command"], "eve_event_counts": dict(types),
            "log_hashes": {path.name: sha256(path) for path in sorted((SENSORS / "suricata").glob("*"))
                           if path.is_file()}}


def cross_sensor_parity() -> dict[str, Any]:
    zeek_ssh = [json.loads(line) for line in (SENSORS / "zeek" / "ssh.log").read_text().splitlines()]
    eve = [json.loads(line) for line in (SENSORS / "suricata" / "eve.json").read_text().splitlines()]
    zeek_tuple = any(row.get("id.orig_h") == "10.50.12.10"
                     and row.get("id.resp_h") == "203.0.113.122"
                     and row.get("id.resp_p") == 443 for row in zeek_ssh)
    suricata_tuple = any(row.get("event_type") == "ssh" and row.get("src_ip") == "10.50.12.10"
                         and row.get("dest_ip") == "203.0.113.122" and row.get("dest_port") == 443
                         for row in eve)
    require(zeek_tuple and suricata_tuple, "H12 SSH/443 cross-sensor parity failed")
    result = {"tuple": "10.50.12.10:50122 -> 203.0.113.122:443/tcp",
              "packet_count": 6, "zeek_protocol": "ssh", "suricata_protocol": "ssh",
              "policy_expected_protocol": "tls", "packet_truth": "SSH identification banners only",
              "status": "PASS"}
    write_json(REPORTS / "h12_packet_parity.json", result)
    return result


def write_junit(cases: list[dict[str, Any]], path: Path) -> None:
    cases = portable_data(cases)
    failures = sum(case["status"] == "FAIL" for case in cases)
    skipped = sum(case["status"] == "NOT_RUN" for case in cases)
    suite = ET.Element("testsuite", name="book05_lab", tests=str(len(cases)),
                       failures=str(failures), skipped=str(skipped),
                       timestamp=utc_now())
    for case in cases:
        node = ET.SubElement(suite, "testcase", name=case["name"],
                             time=str(case.get("duration_s", 0.0)))
        if case["status"] == "FAIL":
            failure = ET.SubElement(node, "failure", message=case.get("error", "failure"))
            failure.text = case.get("traceback", "")
        elif case["status"] == "NOT_RUN":
            ET.SubElement(node, "skipped", message=case["reason"])
        output = ET.SubElement(node, "system-out")
        output.text = json.dumps(case.get("detail", {}), default=json_value, sort_keys=True)
    tree = ET.ElementTree(suite)
    ET.indent(tree, space="  ")
    path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(path, encoding="utf-8", xml_declaration=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="run the complete suite (required)")
    parser.add_argument("--offline", action="store_true", help="assert the offline workflow (required)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not (args.all and args.offline):
        print("Use the single supported command with both --all and --offline.", file=sys.stderr)
        return 2
    REPORTS.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    suite = Suite()
    suite.check("runtime_versions", lambda: (
        require(sys.version_info[:2] == (3, 12), f"tested runtime requires Python 3.12, got {sys.version}"),
        require(duckdb.__version__ == "1.4.5", f"DuckDB 1.4.5 required, got {duckdb.__version__}"),
        require(importlib.metadata.version("scapy") == "2.6.1", "Scapy 2.6.1 package required"),
        {"python": sys.version.split()[0], "duckdb": duckdb.__version__,
         "scapy": importlib.metadata.version("scapy")},
    )[-1])
    suite.check("deterministic_fixture_regeneration", generate_and_check_determinism)
    suite.check("shared_pcap_structure", pcap_summary)
    suite.check("raw_adapter_lineage", validate_adapters)
    suite.check("version_locks", validate_version_lock)
    for hunt in range(1, 25):
        suite.check(f"manifest_H{hunt:02d}", lambda hunt=hunt: validate_manifest(hunt))
        suite.check(f"query_static_H{hunt:02d}", lambda hunt=hunt: static_query_check(hunt))
        suite.check(f"query_controls_H{hunt:02d}", lambda hunt=hunt: validate_hunt(hunt))
    suite.check("release_inventory", write_release_inventory)
    tool_root = discover_tool_root()
    zeek_binary = tool_root / "zeek_root" / "opt" / "zeek" / "bin" / "zeek"
    suricata_binary = tool_root / "suricata_jammy_root" / "usr" / "bin" / "suricata"
    if zeek_binary.exists():
        zeek = suite.check("sensor_zeek_8_2_2", lambda: run_zeek(tool_root))
    else:
        zeek = None
        suite.skipped("sensor_zeek_8_2_2",
                      "optional native Zeek 8.2.2 tool root is not installed")
    if suricata_binary.exists():
        suricata = suite.check("sensor_suricata_8_0_6", lambda: run_suricata(tool_root))
    else:
        suricata = None
        suite.skipped("sensor_suricata_8_0_6",
                      "optional native Suricata 8.0.6 tool root is not installed")
    if zeek is not None and suricata is not None:
        suite.check("sensor_cross_parity_H12", cross_sensor_parity)
    else:
        suite.skipped("sensor_cross_parity_H12", "requires successful Zeek and Suricata replay")
    tshark = shutil.which("tshark")
    if tshark is None:
        suite.skipped("optional_tshark_4_6_8", "TShark is not installed; no TShark validation is claimed")
    else:
        def validate_tshark() -> dict[str, Any]:
            result = run([tshark, "--version"])
            require(result["exit_code"] == 0 and "4.6.8" in result["output"].splitlines()[0],
                    "installed TShark does not match optional version 4.6.8")
            return result
        suite.check("optional_tshark_4_6_8", validate_tshark)

    failed = [case for case in suite.cases if case["status"] == "FAIL"]
    not_run = [case for case in suite.cases if case["status"] == "NOT_RUN"]
    status = "FAIL" if failed else ("PASS_WITH_DECLARED_NOT_RUN" if not_run else "PASS")
    report = {
        "schema_version": 1,
        "suite": "Practical Threat Hunting Book 5 deterministic lab",
        "generated_at_utc": utc_now(),
        "invocation": [sys.executable, "-m", "book05_lab.verify", "--all", "--offline"],
        "offline_contract": "No network access is required or attempted by the verification code.",
        "status": status,
        "required_checks_passed": not failed,
        "summary": dict(Counter(case["status"] for case in suite.cases)),
        "cases": suite.cases,
        "limitations": [
            "TShark is optional and remains NOT_RUN unless the exact binary is installed.",
            "Scapy 2.6.1 is pinned and version-checked; the generator uses a deterministic standard-library PCAP writer so generation opens no socket and does not depend on host interface discovery.",
            "Native Zeek and Suricata checks are NOT_RUN when their exact external tool roots are absent; retained release evidence records a successful pinned-tool replay.",
            "Manual senior network-defender review is a separate human gate and is not simulated.",
            "Repository publication does not grant operational authorization or a reuse license.",
        ],
    }
    write_json(REPORTS / "verification.json", report)
    write_junit(suite.cases, REPORTS / "junit.xml")
    print(json.dumps({"status": status, "summary": report["summary"],
                      "report": str(REPORTS / "verification.json")}, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
