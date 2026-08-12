from Rev_Exp.scripts.plot_all import FIGURE_METRICS
from Rev_Exp.src.common import load_config, summary
from Rev_Exp.src.experiments import derive_exp05b_rows
from Rev_Exp.src.planning import plan_totals, workload_plan


def test_standard_tiered_plan_has_expected_formal_sample_count():
    config = load_config("Rev_Exp/configs/standard.yaml")
    totals = plan_totals(config)
    assert totals["formal_samples"] == 1010
    assert totals["warmup_invocations"] == 397


def test_full_large_endpoint_and_exp05b_reuse_counts():
    rows = workload_plan(load_config("Rev_Exp/configs/full.yaml"))
    exp01_endpoint = next(row for row in rows
                          if row["experiment"] == "Exp01" and
                          row["tier"] == "large_endpoint")
    exp05b = next(row for row in rows if row["experiment"] == "Exp05-B")
    assert exp01_endpoint["formal_samples"] == 27
    assert exp05b["formal_samples"] == 0
    assert exp05b["estimated_crypto_invocations"] == 0
    assert exp05b["reused_formal_samples"] == 149


def test_privacy_update_is_placement_independent():
    rows = workload_plan(load_config("Rev_Exp/configs/standard.yaml"))
    exp06 = next(row for row in rows if row["experiment"] == "Exp06")
    assert exp06["placements"] == 1
    assert exp06["formal_samples"] == 70


def test_statistical_summary_includes_placement_range_fields():
    result = summary([1, 2, 4, 8, 16])
    assert result["min"] == 1
    assert result["max"] == 16
    assert result["p05"] < result["median"] < result["p95"]


def test_exp05b_rows_are_one_to_one_exp01_five_percent_views():
    config = load_config("Rev_Exp/configs/standard.yaml")
    source = []
    for index, n in enumerate(config["exp05"]["dual_scalability"]["n"]):
        source.append({
            "experiment": "exp01", "mode": "standard", "master_seed": "20260811",
            "placement_seed": str(index), "crypto_seed": str(100 + index),
            "crypto_repeat": "2", "repeat": "2", "n": str(n),
            "r_v": str(round(n * 0.05)), "revocation_ratio": "0.05",
            "cover_size": str(10 + index), "rev_time_ns": "1000",
            "rev_time_ms": "0.001", "revkeyupt_time_ms": "0.009",
            "total_ns": "9000", "dual_epoch_total_ms": "0.01",
            "kunodes_ns": "100", "ku_crypto_ns": "8800",
            "warmup": "2", "configured_repeat": "5", "placement_count": "5",
            "gc_enabled": "True", "sampling_tier": "default",
        })
    source.append({**source[0], "revocation_ratio": "0.01"})
    derived = derive_exp05b_rows(source, config)
    assert len(derived) == 4
    identity = ("master_seed", "placement_seed", "crypto_seed", "repeat",
                "n", "r_v", "cover_size")
    selected = source[:4]
    assert all(all(left[key] == right[key] for key in identity)
               for left, right in zip(selected, derived))
    assert all(row["source_experiment"] == "exp01" for row in derived)


def test_figures_use_distinct_measured_views():
    assert FIGURE_METRICS["exp01"] == "revkeyupt_time_ms"
    assert FIGURE_METRICS["exp05_scalability"] == "dual_epoch_total_ms"
