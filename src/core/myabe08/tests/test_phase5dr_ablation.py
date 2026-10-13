"""Internal algebra-only row-randomness ablation; no public wire/profile claim."""
import pytest

from core.myabe08.af import ProtectedPayloadAF
from core.myabe08.algebra import (
    AlgebraOperationCounts, derive_ephemeral_algebra, encrypt_algebra_core,
    finaldec_algebra_core, keygen_algebra_core, setup_algebra_core,
    transform_algebra_core, UserRecoveryScalar,
)
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import ContractError, Unauthorized
from core.myabe08.tests.algebra_fixtures import SYS_ID, policy, token


CASES = (
    (('A',), ((1,),), ('A',), 1),
    (('A', 'B'), ((1, 1), (0, -1)), ('A', 'B'), 1),
    (('A', 'B'), ((1,), (1,)), ('B',), 1),
    (('A', 'B', 'C'), ((1, 1), (1, 2), (1, 3)), ('A', 'C'), 1),
    (('A', 'B', 'C', 'D', 'E'),
     ((1, 1, 1), (1, 2, 4), (1, 3, 9), (1, 4, 16), (1, 5, 25)),
     ('A', 'C', 'E'), 1),
    (('A', 'B', 'A', 'C', 'A'),
     ((0, 0), (0, 0), (1, 1), (0, 0), (0, -1)), ('A',), 3),
    (('A',) * 8, ((1,),) * 8, ('A',), 8),
)


@pytest.mark.parametrize('labels,rows,user,cmax', CASES)
def test_row_independent_ablation_decrypts_and_counts(labels, rows, user, cmax):
    backend = BLS12381Backend(SYS_ID)
    pp, msk = setup_algebra_core(backend, cmax)
    base, rk = keygen_algebra_core(pp, msk, backend)
    matrix, tokens, ranks, header, ctx_af, index = policy(
        backend, labels, rows, cmax)
    assert len(ranks) == len(labels)
    core_counts, row_counts = AlgebraOperationCounts(), AlgebraOperationCounts()
    core = encrypt_algebra_core(pp, matrix, tokens, backend, counts=core_counts)
    row = encrypt_algebra_core(pp, matrix, tokens, backend, counts=row_counts,
                               component_allocation='ROW')
    assert len(core.d_j) == cmax
    assert len(row.d_j) == len(labels)
    assert core_counts.g2_exponentiations == cmax
    assert row_counts.g2_exponentiations == len(labels)
    user_tokens = tuple(sorted({token(label) for label in user}))
    bundle = derive_ephemeral_algebra(pp, base, user_tokens, row.c, backend)
    transform_counts = AlgebraOperationCounts()
    transformed = transform_algebra_core(
        pp, row, bundle, index, header, ctx_af, backend, counts=transform_counts,
        component_allocation='ROW')
    _, recovered = finaldec_algebra_core(bundle.t0_q, transformed.t_a, rk, backend)
    assert recovered == row.e
    assert transform_counts.pairing_terms == 1 + len(transformed.reconstruction_rows)
    assert transformed.occurrence_slots == transformed.reconstruction_rows
    wrong_rk = UserRecoveryScalar(backend.binding, backend.scalar_from_int(2))
    if wrong_rk != rk:
        _, wrong = finaldec_algebra_core(bundle.t0_q, transformed.t_a,
                                         wrong_rk, backend)
        assert wrong != row.e
    if len(labels) != cmax:
        with pytest.raises(ContractError):
            transform_algebra_core(pp, row, bundle, index, header, ctx_af, backend)


def test_row_independent_ablation_unauthorized_rejects():
    backend = BLS12381Backend(SYS_ID)
    pp, msk = setup_algebra_core(backend, 1)
    base, _ = keygen_algebra_core(pp, msk, backend)
    matrix, tokens, _, header, ctx_af, index = policy(
        backend, ('A', 'B'), ((1, 1), (0, -1)), 1)
    row = encrypt_algebra_core(pp, matrix, tokens, backend,
                               component_allocation='ROW')
    bundle = derive_ephemeral_algebra(pp, base, (token('A'),), row.c, backend)
    with pytest.raises(Unauthorized):
        transform_algebra_core(pp, row, bundle, index, header, ctx_af, backend,
                               component_allocation='ROW')


def test_phase5dr_group_byte_accounting_excludes_internal_e():
    from core.myabe08.baselines.phase5dr_bench import (
        _run_ablation, _run_core, plan,
    )
    config = plan()['configurations'][0]
    # The helper uses its own fixed SysID, so a matching backend is required.
    from core.myabe08.baselines.phase5dr_bench import SYS_ID as BENCH_SYS_ID
    backend = BLS12381Backend(BENCH_SYS_ID)
    baseline = _run_ablation(backend, config, 'OCCURRENCE')
    ablation = _run_ablation(backend, config, 'ROW')
    assert (baseline['core_ct_bytes'], ablation['core_ct_bytes']) == (624, 1488)
    assert baseline['gt_count'] == ablation['gt_count'] == 0
    assert baseline['internal_kem_gt_count'] == ablation['internal_kem_gt_count'] == 1
    core_config = next(c for c in plan()['configurations'] if c['track'] == 'core')
    core = _run_core(backend, core_config, 'MYABE08_BLS12381_CORE')
    assert core['ct_group_bytes'] == 384  # 5 C_i, one D_1, one C; no E.
