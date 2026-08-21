"""Unit tests for the statistics / aggregation / planning helpers that back
the validation pipeline (median+IQR, blank/N-A handling, runtime projection).
"""

import json

import pytest

from Global_Exp.src.planning import point_weight
from Global_Exp.src.statistics import percentile, summary
from Global_Exp.scripts.aggregate import _numeric_groups


def test_percentile_interpolation():
    values = [0, 10, 20, 30]
    assert percentile(values, 0.0) == 0
    assert percentile(values, 1.0) == 30
    assert percentile(values, 0.5) == 15  # (10+20)/2


def test_summary_median_iqr():
    values = [1, 2, 3, 4, 5]
    stats = summary(values)
    assert stats["median"] == 3
    assert stats["count"] == 5
    assert stats["p25"] == 2
    assert stats["p75"] == 4
    assert stats["p95"] == pytest.approx(4.8)  # linear interpolation
    assert stats["min"] == 1 and stats["max"] == 5


def test_summary_never_drops_outliers():
    values = [1, 2, 3, 4, 500]
    stats = summary(values)
    assert stats["max"] == 500
    assert stats["p95"] == pytest.approx(400.8)  # outlier retained in the tail
    assert stats["median"] == 3  # median robust to the tail


def test_numeric_groups_skips_blank_and_na():
    rows = [
        # FABEO22 executes encrypt but has no transform metric (blank)
        {"scheme": "FABEO22", "policy_rows": "8", "user_attrs": "8",
         "status": "ok", "transform_ms": "", "encrypt_total_ms": "10"},
        {"scheme": "FXABE-Full", "policy_rows": "8", "user_attrs": "8",
         "status": "ok", "transform_ms": "42.5", "encrypt_total_ms": "80"},
        {"scheme": "FXABE-Full", "policy_rows": "8", "user_attrs": "8",
         "status": "ok", "transform_ms": "40.0", "encrypt_total_ms": "78"},
        {"scheme": "FXABE-Full", "policy_rows": "8", "user_attrs": "8",
         "status": "na", "transform_ms": "", "encrypt_total_ms": ""},
    ]
    groups = _numeric_groups(rows, ["transform_ms", "encrypt_total_ms"])
    # FABEO22 transform is blank -> absent; its encrypt survives
    assert ("encrypt_total_ms", "FABEO22", "8", "8") in groups
    assert ("transform_ms", "FABEO22", "8", "8") not in groups
    # na rows are skipped entirely
    assert len(groups[("transform_ms", "FXABE-Full", "8", "8")]) == 2
    assert len(groups[("encrypt_total_ms", "FXABE-Full", "8", "8")]) == 2


def test_point_weight_scales_with_policy_rows():
    config = {"schemes": ["FABEO22", "FXABE-Full"], "repetitions": 20,
              "warmups": 3, "policy_rows": [10, 20, 40],
              "user_attrs": [5, 10, 20], "exp08": {}}
    exp03 = point_weight(config, "exp03")
    # (10+20+40) rows * (20+3) samples * 2 schemes
    assert exp03 == (10 + 20 + 40) * (20 + 3) * 2
    assert point_weight(config, "exp01") == (20 + 3) * 2
    # provisioning scales with |S|, not l
    exp02 = point_weight(config, "exp02")
    assert exp02 == (5 + 10 + 20) * (20 + 3) * 2
    assert point_weight(config, "exp02") != exp03


def test_planning_projection_is_linear():
    from Global_Exp.src.planning import project
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = Path(tmp)
        (run_dir / "logs").mkdir()
        with open(run_dir / "logs" / "timing.json", "w") as handle:
            json.dump({"exp03": 60.0, "exp06": 120.0}, handle)
        small = {"schemes": ["FABEO22", "FXABE-Full"], "repetitions": 5,
                 "warmups": 1, "policy_rows": [10, 20],
                 "user_attrs": [5, 10], "exp08": {}}
        big = {"schemes": ["FABEO22", "FXABE-Full"], "repetitions": 50,
               "warmups": 5, "policy_rows": [10, 20, 40, 80],
               "user_attrs": [5, 10, 20, 40], "exp08": {}}
        result = project(big, run_dir, small)
        exp03_scale = point_weight(big, "exp03") / point_weight(small, "exp03")
        assert result["per_experiment"]["exp03"]["scale"] == pytest.approx(
            exp03_scale)
        assert result["projected_total_seconds"] > 0
