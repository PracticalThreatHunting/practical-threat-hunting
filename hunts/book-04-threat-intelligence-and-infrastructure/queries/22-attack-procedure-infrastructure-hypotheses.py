import hashlib
import json
from collections import Counter
from pathlib import Path

ATTACK_RELEASE = "19.2"

def attack_refs(obj):
    return [r for r in obj.get("external_references", [])
            if r.get("source_name") == "mitre-attack"]

def external_id(obj):
    return next((r.get("external_id") for r in attack_refs(obj)
                 if r.get("external_id")), None)

def active(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)

def load_bundle(path):
    raw = Path(path).read_bytes()
    bundle_sha256 = hashlib.sha256(raw).hexdigest()
    bundle = json.loads(raw.decode("utf-8"))
    if bundle.get("type") != "bundle":
        raise ValueError("Expected a STIX bundle")
    objects = [obj for obj in bundle.get("objects", []) if obj.get("id")]
    version_keys = [(obj["id"], obj.get("modified")) for obj in objects]
    counts = Counter(version_keys)
    duplicates = sorted(key for key, count in counts.items() if count > 1)
    if duplicates:
        raise ValueError(f"Duplicate STIX object versions: {duplicates[:5]}")

    # STIX versions retain the same id. Select the latest retained version for
    # this pinned ATT&CK snapshot while preserving the complete input bundle.
    by_id = {}
    for obj in sorted(objects, key=lambda item: (
            item["id"], item.get("modified") or item.get("created") or "")):
        by_id[obj["id"]] = obj
    return by_id, list(by_id.values()), bundle_sha256

def procedure_relationships(bundle_path, technique_external_id):
    by_id, objects, bundle_sha256 = load_bundle(bundle_path)
    techniques = {obj["id"]: obj for obj in objects
                  if obj.get("type") == "attack-pattern"
                  and external_id(obj) == technique_external_id and active(obj)}
    rows = []
    for rel in objects:
        if rel.get("type") != "relationship" or not active(rel):
            continue
        if rel.get("relationship_type") != "uses" or rel.get("target_ref") not in techniques:
            continue
        source = by_id.get(rel.get("source_ref"))
        if not source:
            continue
        target = techniques[rel["target_ref"]]
        rows.append({
            "relationship_id": rel.get("id"),
            "relationship_active": True,
            "source_stix_id": source.get("id"),
            "source_type": source.get("type"),
            "source_name": source.get("name"),
            "source_active": active(source),
            "source_attack_id": external_id(source),
            "attack_release": ATTACK_RELEASE,
            "attack_bundle_sha256": bundle_sha256,
            "source_object_version": source.get("x_mitre_version"),
            "source_external_references": source.get("external_references", []),
            "technique_stix_id": target.get("id"),
            "technique_id": external_id(target),
            "technique_name": target.get("name"),
            "technique_object_version": target.get("x_mitre_version"),
            "procedure_description": rel.get("description"),
            "relationship_modified": rel.get("modified"),
            "relationship_external_references": rel.get("external_references", []),
        })
    return rows
