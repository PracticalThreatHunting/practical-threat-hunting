from collections import defaultdict
from statistics import median

def jaccard(left, right):
    union = left | right
    return None if not union else len(left & right) / len(union)

def dns_rotation_features(samples):
    ordered = sorted(samples, key=lambda row: row["observed_at"])
    answer_sets = []
    ttls = []
    addresses, prefixes, asns = set(), set(), set()
    by_vantage = defaultdict(set)

    for row in ordered:
        current = set(row["addresses"])
        answer_sets.append(current)
        addresses.update(current)
        ttls.extend(row["ttls"])
        prefixes.update(row["prefixes_at_observation"])
        asns.update(row["origin_asns_at_observation"])
        by_vantage[row["vantage_id"]].update(current)

    adjacent_similarity = [
        score for i in range(1, len(answer_sets))
        if (score := jaccard(answer_sets[i - 1], answer_sets[i])) is not None
    ]
    return {
        "sample_count": len(ordered),
        "unique_address_count": len(addresses),
        "unique_prefix_count": len(prefixes),
        "unique_asn_count": len(asns),
        "median_ttl": median(ttls) if ttls else None,
        "median_adjacent_jaccard": (
            median(adjacent_similarity) if adjacent_similarity else None
        ),
        "vantage_count": len(by_vantage),
    }
