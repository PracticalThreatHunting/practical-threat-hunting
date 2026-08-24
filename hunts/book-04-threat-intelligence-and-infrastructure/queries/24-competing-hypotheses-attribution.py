from collections import Counter

ALLOWED = {"supports", "contradicts", "not-discriminating",
           "unknown", "not-applicable"}

def validate_matrix(hypotheses, evidence_items, assessments):
    errors = []
    hypothesis_ids = {h["hypothesis_id"] for h in hypotheses}
    evidence_ids = {e["evidence_id"] for e in evidence_items}
    counts = Counter((a.get("evidence_id"), a.get("hypothesis_id"))
                     for a in assessments)
    for key, count in counts.items():
        if count > 1:
            errors.append(f"duplicate assessment: {key}")
    by_pair = {(a["evidence_id"], a["hypothesis_id"]): a
               for a in assessments if a.get("evidence_id") in evidence_ids
               and a.get("hypothesis_id") in hypothesis_ids}
    for cell in assessments:
        if cell.get("evidence_id") not in evidence_ids:
            errors.append(f"unknown evidence ID: {cell.get('evidence_id')}")
        if cell.get("hypothesis_id") not in hypothesis_ids:
            errors.append(f"unknown hypothesis ID: {cell.get('hypothesis_id')}")
    for evidence_id in evidence_ids:
        for hypothesis_id in hypothesis_ids:
            key = (evidence_id, hypothesis_id)
            cell = by_pair.get(key)
            if not cell:
                errors.append(f"missing assessment: {key}")
                continue
            if cell.get("effect") not in ALLOWED:
                errors.append(f"invalid effect: {key}")
            if not cell.get("reason"):
                errors.append(f"missing reason: {key}")
            if not cell.get("analyst") or not cell.get("assessment_version"):
                errors.append(f"missing provenance: {key}")
    return errors

def source_families_for(evidence_items):
    return {
        item["evidence_id"]: (
            item.get("source_dependency_id") or "UNKNOWN_DEPENDENCY"
        )
        for item in evidence_items
    }
