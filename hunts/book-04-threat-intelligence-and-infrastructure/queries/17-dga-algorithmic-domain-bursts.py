from collections import Counter, defaultdict
from datetime import datetime, timezone
from math import log2

def entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * log2(n / length) for n in counts.values())

def features(qname):
    name = qname.rstrip(".").lower()
    label = name.split(".")[0]
    letters = [c for c in label if c.isalpha()]
    digits = [c for c in label if c.isdigit()]
    vowels = [c for c in letters if c in "aeiou"]
    return {
        "label_length": len(label),
        "entropy": round(entropy(label), 3),
        "digit_ratio": round(len(digits) / max(len(label), 1), 3),
        "vowel_ratio": round(len(vowels) / max(len(letters), 1), 3),
        "unique_ratio": round(len(set(label)) / max(len(label), 1), 3),
    }

def minute_bucket(iso_time, width_minutes=10):
    t = datetime.fromisoformat(iso_time.replace("Z", "+00:00")).astimezone(timezone.utc)
    minute = (t.minute // width_minutes) * width_minutes
    return t.replace(minute=minute, second=0, microsecond=0).isoformat()

def build_bursts(events):
    bursts = defaultdict(list)
    for event in events:
        key = (event["asset_id"], minute_bucket(event["event_time"]))
        row = dict(event)
        row["features"] = features(event["qname"])
        bursts[key].append(row)

    results = []
    for (asset_id, bucket), rows in bursts.items():
        names = {r["qname"] for r in rows}
        nxdomain = sum(r["rcode"] == "NXDOMAIN" for r in rows)
        high_entropy = sum(r["features"]["entropy"] >= 3.0 for r in rows)
        results.append({
            "asset_id": asset_id,
            "bucket": bucket,
            "unique_names": len(names),
            "nxdomain_ratio": round(nxdomain / max(len(rows), 1), 3),
            "high_entropy_ratio": round(high_entropy / max(len(rows), 1), 3),
            "raw_event_ids": [r["raw_event_id"] for r in rows],
        })
    return results
