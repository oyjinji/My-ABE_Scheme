from Code.fxdacp import OperationMetrics


def test_empty_and_partial_hits_keep_exact_pairing_formula(scheme):
    pk, msk = scheme.setup()
    ct = scheme.encrypt(pk, msk, b"partial", "(A and B)", epoch="5")
    for attrs, expected_r in [(["Z"], 0), (["A"], 1), (["A", "B"], 2)]:
        tk, _ = scheme.keygen(pk, msk, attrs, epoch="5")
        metrics = OperationMetrics()
        scheme.transform(pk, ct, tk, metrics=metrics)
        values = metrics.as_dict()
        assert values["r"] == expected_r
        assert values["pairing_count"] == 1 + 2 * expected_r
