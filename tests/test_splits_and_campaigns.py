import csv
import json
from collections import Counter
from pathlib import Path

from scripts.build_campaigns import clopper_pearson, get_split_mapping


def test_pairs_disjointness() -> None:
    """Every pair in the eval dataset must belong to exactly one split."""
    pairs_file = Path("data/eval_pairs.csv")
    assert pairs_file.exists()
    pairs = [
        p for p in csv.DictReader(open(pairs_file, encoding="utf-8")) if p.get("status") == "ok"
    ]
    assert len(pairs) == 1349

    k2s = get_split_mapping()
    pair_splits: dict[str, str] = {}
    split_counts: Counter[str] = Counter()

    for p in pairs:
        key = f"{p['package']}@{p['old_version']}@{p['new_version']}"
        s = k2s[(p["package"], p["old_version"], p["new_version"])]
        assert key not in pair_splits, f"Duplicate pair {key}"
        pair_splits[key] = s
        split_counts[s] += 1

    assert split_counts["DEV"] == 857
    assert split_counts["VAL"] == 94
    assert split_counts["TEST-A"] == 299
    assert split_counts["TEST-B"] == 99
    assert sum(split_counts.values()) == 1349


def test_campaigns_disjointness() -> None:
    """Every campaign must belong to exactly one split (by earliest discovery date)."""
    camps_file = Path("data/eval_campaigns.json")
    assert camps_file.exists()
    camps = json.load(open(camps_file, encoding="utf-8"))
    assert len(camps) == 84

    split_counts: Counter[str] = Counter()
    seen_cids: set[str] = set()

    for cid, c in camps.items():
        assert cid not in seen_cids
        seen_cids.add(cid)
        split = c["primary_split"]
        assert split in ("DEV", "VAL", "TEST-A", "TEST-B")
        split_counts[split] += 1

    assert split_counts["DEV"] == 29
    assert split_counts["VAL"] == 3
    assert split_counts["TEST-A"] == 49
    assert split_counts["TEST-B"] == 3
    assert sum(split_counts.values()) == 84


def test_clopper_pearson_bounds() -> None:
    """Test exact Clopper-Pearson binomial confidence interval properties."""
    # Degenerate cases
    lo0, hi0 = clopper_pearson(0, 3)
    assert lo0 == 0.0
    assert 0.70 < hi0 < 0.71

    lo3, hi3 = clopper_pearson(3, 3)
    assert 0.29 < lo3 < 0.30
    assert hi3 == 1.0

    # Intermediate cases
    lo, hi = clopper_pearson(20, 29)
    assert 0.0 <= lo <= hi <= 1.0
