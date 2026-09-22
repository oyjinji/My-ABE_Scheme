import random

from core.fxabe_rev.filters import create_index
from experiments.index_v2.benchmarks.common import derive_seed
from experiments.index_v2.benchmarks.workload import f1_workload


def test_workload_and_filter_seed_reproduce_structure():
    seed = derive_seed(9, "point")
    first = f1_workload(16, "F1-B", seed)
    second = f1_workload(16, "F1-B", seed)
    assert first == second
    left = create_index("FX-ABF").build(first["entries"], b"ctx", random.Random(seed))
    right = create_index("FX-ABF").build(second["entries"], b"ctx", random.Random(seed))
    assert left.state["slots"] == right.state["slots"]
    assert left.state["seed"] == right.state["seed"]
