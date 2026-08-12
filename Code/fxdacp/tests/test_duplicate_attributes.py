from Code.fxdacp import OperationMetrics


def test_duplicate_policy_attribute_reuses_token_but_not_rows(scheme):
    pk, msk = scheme.setup()
    tk, rk = scheme.keygen(pk, msk, ["A"], epoch="3")
    metrics = OperationMetrics()
    policy = {"matrix": [[1, 1], [0, -1], [1, 0]], "rho": ["A", "A", "B"]}
    ct = scheme.encrypt(pk, msk, b"duplicates", policy, epoch="3", metrics=metrics)
    assert metrics.as_dict()["ell"] == 3
    assert metrics.as_dict()["u"] == 2
    assert metrics.as_dict()["oprf_count"] == 2
    ctx = scheme._context("1", "3", 2, 3, ct["C"], ct["A_star"])
    result = scheme.indexer.query(ct["index"], tk["items"][0]["token_bytes"], ctx)
    assert result.hit and result.posting_list == (1, 2)
    transformed = scheme.transform(pk, ct, tk)
    assert set(transformed["transformed_rows"]) == {1, 2}
    assert scheme.final_dec(pk, transformed, rk) == b"duplicates"


def test_user_attribute_input_is_deduplicated(scheme):
    pk, msk = scheme.setup()
    metrics = OperationMetrics()
    tk, _ = scheme.keygen(pk, msk, ["A", "A"], epoch="3", metrics=metrics)
    assert len(tk["items"]) == 1
    assert metrics.as_dict()["token_generation_count"] == 1
