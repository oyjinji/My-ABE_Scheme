from pathlib import Path

from core.fxabe_05_3_exp.fx import FXIndex
from experiments.perf_05_3.scripts.common import SCHEMA, base_row
from experiments.perf_05_3.workloads import (distinct_token_workload,
                                    duplicate_workload, or_workload,
                                    threshold_workload)


def test_raw_schema_is_complete():
    required = {
        "run_id", "experiment", "scheme", "curve", "backend", "workload", "seed", "replicate",
        "ell", "u", "N", "J", "k", "t_I", "c_max", "actual_c_star", "n_users", "n_revoked",
        "phase", "time_ns", "G1_exp", "G2_exp", "GT_exp", "pair_count",
        "serialized_bytes", "component", "success", "notes",
    }
    assert required <= set(SCHEMA)
    assert set(base_row("r", "e", "s", 1, 0)) == set(SCHEMA)


def test_workload_shapes(group):
    work = or_workload(group, 20, matched=5)
    assert len(work.policy["A"]) == len(work.policy["rho"]) == 20
    assert len(work.user_attributes) == 5 and work.k == 1
    threshold = threshold_workload(group, 8, 4)
    assert len(threshold.policy["A"]) == 8 and len(threshold.policy["A"][0]) == 4
    duplicate = duplicate_workload(group, 8, 4)
    assert len(set(duplicate.policy["rho"])) == 2
    sensitivity = distinct_token_workload(group, 640, 80)
    assert len(sensitivity.policy["rho"]) == 640
    assert len(set(sensitivity.policy["rho"])) == 80
    assert max(sensitivity.policy["rho"].count(x)
               for x in set(sensitivity.policy["rho"])) == 8


def test_fx_final_state_and_accounting():
    entries = {b"a": (1, 3), b"b": (2,)}
    index = FXIndex.build(entries, b"ctx", 3, seed=77)
    assert not index.has_exact_locator()
    assert not hasattr(index, "__dict__")
    assert index.query(b"a", b"ctx").posting_list == (1, 3)
    assert not index.query(b"missing", b"ctx").hit
    accounting = index.accounting()
    assert accounting["FX_PStore_serialized_bytes"] == (
        accounting["FX_slot_bytes"] + accounting["FX_metadata_bytes"] +
        accounting["PStore_nonce_bytes"] + accounting["PStore_ciphertext_bytes"]
    )


def test_no_object_size_api():
    roots = [Path("src/core/fxabe_05_3_exp"), Path("src/experiments/perf_05_3")]
    for root in roots:
        for path in root.rglob("*.py"):
            assert ("sys." + "getsizeof") not in path.read_text(), path
