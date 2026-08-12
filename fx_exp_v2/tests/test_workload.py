from fx_exp_v2.benchmarks.workload import f1_workload, transform_attributes


def test_f1_shapes_and_canonical_postings():
    a = f1_workload(32, "F1-A", 1)
    b = f1_workload(32, "F1-B", 1)
    assert a["u"] == a["ell"] == 32
    assert b["u"] == 32 and b["ell"] == 128
    assert sum(map(len, b["entries"].values())) == 128
    assert all(rows == sorted(set(rows)) for rows in b["entries"].values())


def test_transform_attribute_hit_count():
    attributes = transform_attributes(64, 32, 8)
    assert len(attributes) == 32
    assert sum(item.startswith("policy-") for item in attributes) == 8
