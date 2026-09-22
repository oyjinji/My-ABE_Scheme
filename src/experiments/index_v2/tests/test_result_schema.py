from experiments.index_v2.benchmarks.benchmark_f1_build_space import FIELDS as F1
from experiments.index_v2.benchmarks.benchmark_f2_transform_scaling import FIELDS as F2
from experiments.index_v2.benchmarks.benchmark_f3_correctness import FIELDS as F3


def test_required_raw_fields_exist():
    assert {
        "integrated_index_bytes", "locator_bytes", "retry_ms",
        "component_sum_ms", "timing_residual_ms", "pstore_build_count",
        "structure_build_ms", "locator_build_ms", "pstore_build_ms",
        "metadata_build_ms", "integrated_build_ms", "display_name",
    } <= set(F1)
    assert {
        "core_transform_ms", "transform_total_ms", "pairing_count",
        "membership_or_retrieval_ms", "locator_lookup_ms", "pstore_kdf_ms",
        "pstore_aead_ms", "posting_decode_ms", "integrated_index_query_ms",
        "display_name",
    } <= set(F2)
    assert {"member_false_negative_count", "final_false_accept_count"} <= set(F3)
    for fields in (F1, F2, F3):
        assert {"master_seed", "workload_seed", "filter_seed", "scheme_seed"} <= set(fields)
