from __future__ import annotations

import json
from itertools import combinations
from pathlib import Path

MIN_SHARED = 4
MIN_JACCARD = 0.55


def load_features(path: Path) -> dict[str, dict]:
    pages: dict[str, dict] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            required = {"capture_id", "observed_at", "source", "features"}
            missing = required.difference(row)
            if missing:
                raise ValueError(f"missing fields: {sorted(missing)}")
            row["features"] = set(row["features"])
            pages[row["capture_id"]] = row
    return pages


def compare(left: set[str], right: set[str]) -> tuple[int, float]:
    shared = left & right
    union = left | right
    score = len(shared) / len(union) if union else 0.0
    return len(shared), score


pages = load_features(Path("approved_page_features.jsonl"))
for left_id, right_id in combinations(sorted(pages), 2):
    shared_count, jaccard = compare(
        pages[left_id]["features"], pages[right_id]["features"]
    )
    if shared_count >= MIN_SHARED and jaccard >= MIN_JACCARD:
        print(json.dumps({
            "left": left_id,
            "right": right_id,
            "shared_count": shared_count,
            "jaccard": round(jaccard, 3),
            "left_observed_at": pages[left_id]["observed_at"],
            "right_observed_at": pages[right_id]["observed_at"],
            "left_source": pages[left_id]["source"],
            "right_source": pages[right_id]["source"],
        }, sort_keys=True))
