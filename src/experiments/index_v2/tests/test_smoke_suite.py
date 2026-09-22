from pathlib import Path

from fx_exp_v2.analysis.summarize_results import summarize_run
from fx_exp_v2.analysis.validate_results import validate
from fx_exp_v2.benchmarks.common import dump_json, dump_yaml
from fx_exp_v2.benchmarks.run_suite import run_benchmarks


def test_tiny_real_suite(tmp_path):
    config = {
        "mode": "test", "master_seed": 7, "pairing_group": "MNT224",
        "filters": [
            "Legacy ABF", "Bloom+Locator", "Cuckoo+Locator",
            "Xor+Locator", "FX-ABF",
        ],
        "f1": {"u": [8], "independent_seeds": 1, "warmup_builds": 0,
               "measured_builds_per_seed": 1},
        "f2": {"ell_scaling": [4], "fixed_N_a": 2, "fixed_r_a": 1,
               "fixed_ell_b": 4, "fixed_N_b": 2, "r_scaling": [1],
               "independent_workloads": 1, "warmup_queries": 0,
               "measured_queries": 1},
        "f3": {"u": 8, "member_queries": 8, "nonmember_queries": 20,
               "independent_workloads": 1},
        "bootstrap_resamples": 20, "threads": 1,
    }
    for directory in ("raw", "summary", "figures", "report", "logs"):
        (tmp_path / directory).mkdir()
    dump_yaml(tmp_path / "config_resolved.yaml", config)
    dump_json(tmp_path / "environment.json", {"timestamp": "test"})
    run_benchmarks(config, tmp_path)
    errors, _ = validate(tmp_path)
    assert not errors
    assert (tmp_path / "summary" / "all_metrics.json").exists()
