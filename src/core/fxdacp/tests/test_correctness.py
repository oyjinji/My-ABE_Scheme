from core.fxdacp import OperationMetrics


def round_trip(scheme, attrs, policy, message=b"fxdacp-test", epoch="7"):
    pk, msk = scheme.setup()
    tk, rk = scheme.keygen(pk, msk, attrs, epoch=epoch)
    ct = scheme.encrypt(pk, msk, message, policy, epoch=epoch)
    transformed = scheme.transform(pk, ct, tk)
    return scheme.final_dec(pk, transformed, rk), (pk, msk, tk, rk, ct, transformed)


def test_single_attribute(scheme):
    assert round_trip(scheme, ["A"], "A")[0] == b"fxdacp-test"


def test_and_policy(scheme):
    assert round_trip(scheme, ["A", "B"], "(A and B)")[0] == b"fxdacp-test"


def test_or_policy(scheme):
    assert round_trip(scheme, ["B"], "(A or B)")[0] == b"fxdacp-test"


def test_general_lsss_matrix(scheme):
    policy = {"matrix": [[1, 1], [0, -1]], "rho": ["A", "B"]}
    assert round_trip(scheme, ["A", "B"], policy)[0] == b"fxdacp-test"


def test_unsatisfied_policy_returns_failure(scheme):
    assert round_trip(scheme, ["A"], "(A and B)")[0] is None


def test_wrong_epoch_fails(scheme):
    pk, msk = scheme.setup()
    tk, _ = scheme.keygen(pk, msk, ["A"], epoch="old")
    ct = scheme.encrypt(pk, msk, b"epoch", "A", epoch="new")
    assert scheme.transform(pk, ct, tk) is None
    tk_new, rk_new = scheme.keygen(pk, msk, ["A"], epoch="new")
    assert scheme.final_dec(pk, scheme.transform(pk, ct, tk_new), rk_new) is not None


def test_operation_counts(scheme):
    pk, msk = scheme.setup()
    tk, rk = scheme.keygen(pk, msk, ["A", "B"], epoch="1")
    ct = scheme.encrypt(pk, msk, b"counts", "(A and B)", epoch="1")
    transform_metrics = OperationMetrics()
    transformed = scheme.transform(pk, ct, tk, metrics=transform_metrics)
    assert transform_metrics.as_dict()["pairing_count"] == 1 + 2 * transform_metrics.as_dict()["r"]
    final_metrics = OperationMetrics()
    assert scheme.final_dec(pk, transformed, rk, metrics=final_metrics) == b"counts"
    assert final_metrics.as_dict()["pairing_count"] == 0
