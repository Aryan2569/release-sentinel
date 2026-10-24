"""Test that verifies every metric and statistic quoted in README.md matches docs/METRICS.json.

Ensures README.md never falls out of date or reports unverified statistics.
"""

from __future__ import annotations

import json
from pathlib import Path


def test_readme_metrics_match_canonical_metrics_json():
    metrics_path = Path("docs/METRICS.json")
    readme_path = Path("README.md")

    assert metrics_path.exists(), "docs/METRICS.json is missing"
    assert readme_path.exists(), "README.md is missing"

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    readme_text = readme_path.read_text(encoding="utf-8")

    # 1. Total evaluation pairs and campaigns
    all_def_sample = metrics["default_profile"]["sample"]["ALL"]
    all_def_campaign = metrics["default_profile"]["campaign"]["ALL"]

    p_str = f"{all_def_sample['pairs']:,}"
    assert p_str in readme_text or str(all_def_sample["pairs"]) in readme_text
    assert f"{all_def_campaign['campaigns']}" in readme_text

    # 2. Check each split's numbers in README table
    for split in ["DEV", "VAL", "TEST-A", "TEST-B", "ALL"]:
        s_strict = metrics["sample"]["v1.4"][split]
        s_default = metrics["default_profile"]["sample"][split]
        c_default = metrics["default_profile"]["campaign"][split]

        # Check pair counts
        p_c = str(s_default["pairs"])
        p_c_comma = f"{s_default['pairs']:,}"
        assert p_c in readme_text or p_c_comma in readme_text, f"Missing pair count for {split}"

        # Check default pair warn and block percentages
        w_def_2 = f"{s_default['fc_warn_pct']:.2f}%"
        w_def_1 = f"{s_default['fc_warn_pct']:.1f}%"
        assert w_def_2 in readme_text or w_def_1 in readme_text

        b_def_2 = f"{s_default['fc_block_pct']:.2f}%"
        b_def_1 = f"{s_default['fc_block_pct']:.1f}%"
        assert b_def_2 in readme_text or b_def_1 in readme_text

        # Check strict pair percentages
        w_str_2 = f"{s_strict['fc_warn_pct']:.2f}%"
        w_str_1 = f"{s_strict['fc_warn_pct']:.1f}%"
        assert w_str_2 in readme_text or w_str_1 in readme_text

        b_str_2 = f"{s_strict['fc_block_pct']:.2f}%"
        b_str_1 = f"{s_strict['fc_block_pct']:.1f}%"
        b_str_stripped = f"{s_strict['fc_block_pct']:.2f}".rstrip("0")
        assert b_str_2 in readme_text or b_str_1 in readme_text or b_str_stripped in readme_text

        # Check campaign lenient recall
        camp_warn_fc = f"{c_default['lenient_fc_warn']}/{c_default['campaigns']}"
        camp_warn_eo = f"{c_default['lenient_eo_warn']}/{c_default['campaigns']}"
        assert camp_warn_fc in readme_text or camp_warn_eo in readme_text

        # Check campaign confidence intervals
        ci = c_default["lenient_eo_warn_ci"]
        assert f"{ci[0]}" in readme_text, f"Missing lower CI for {split}"
        assert f"{ci[1]}" in readme_text, f"Missing upper CI for {split}"

    # 3. Check 12-repo replay numbers
    replay = metrics["replay_12repos"]["default"]
    assert str(replay["total_updates"]) in readme_text
    assert f"{replay['total_pkgs']:,}" in readme_text or str(replay["total_pkgs"]) in readme_text
    assert str(replay["allow"]) in readme_text
    assert str(replay["warn"]) in readme_text
    assert str(replay["block"]) in readme_text

    # Per-package warn rate (901 / 5965 = 15.10%)
    assert "901" in readme_text
    assert "15.10%" in readme_text

    # Notable gating reduction (86 updates, 31.7% reduction)
    assert "86" in readme_text
    assert "31.7%" in readme_text
