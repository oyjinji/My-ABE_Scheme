"""FABEO common-backend correctness, separated by tau=1 and multi-use."""
import pytest

from core.myabe08.baselines import fabeo
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import Unauthorized
from core.myabe08.lsss import LSSSMatrix


SYS_ID = b'FABEO22-COMMON-BLS12381-TEST'


@pytest.mark.parametrize('labels,rows,authorized,unauthorized,tau', (
    (('A',), ((1,),), ('A',), ('B',), 1),
    (('A', 'B'), ((1, 1), (0, -1)), ('A', 'B'), ('A',), 1),
    (('A', 'B', 'C'), ((1, 1), (1, 2), (1, 3)), ('A', 'C'), ('A',), 1),
    (('A', 'A'), ((1, 1), (0, -1)), ('A',), ('B',), 2),
    (('A', 'B', 'A'), ((1,), (1,), (1,)), ('A',), ('C',), 2),
    (('A', 'B', 'A', 'C', 'A'), ((1,),) * 5, ('A',), ('D',), 3),
    (('A',) * 4, ((1,),) * 4, ('A',), ('B',), 4),
))
def test_fabeo_common_correctness(labels, rows, authorized, unauthorized, tau):
    backend = BLS12381Backend(SYS_ID)
    pp, alpha = fabeo.setup(backend)
    matrix = LSSSMatrix(rows, backend.scalar_order, len(rows), len(rows[0]))
    message = backend.pair(pp.g1, pp.g2)
    ct = fabeo.encrypt(pp, matrix, labels, message)
    assert max(ct.ranks) == tau
    assert len(ct.g2_sprime) == tau
    assert len(ct.rows) == len(labels)
    good = fabeo.keygen(pp, alpha, authorized)
    assert fabeo.decrypt(pp, ct, good) == message
    bad = fabeo.keygen(pp, alpha, unauthorized)
    with pytest.raises(Unauthorized):
        fabeo.decrypt(pp, ct, bad)


def test_tau1_native_reference_structural_crosscheck():
    charm = pytest.importorskip('charm.toolbox.pairinggroup')
    from core.fabeo22cp import FABEO22CPABE

    group = charm.PairingGroup('MNT224')
    native = FABEO22CPABE(group)
    pk, msk = native.setup()
    native_key = native.keygen(pk, msk, ['A', 'B'])
    native_message = group.random(charm.GT)
    native_ct = native.encrypt(pk, native_message, '(A and B)')
    assert native.decrypt(pk, native_ct, native_key) == native_message

    backend = BLS12381Backend(SYS_ID)
    pp, alpha = fabeo.setup(backend)
    matrix = LSSSMatrix(((1, 1), (0, -1)), backend.scalar_order, 2, 2)
    common_message = backend.pair(pp.g1, pp.g2)
    common_key = fabeo.keygen(pp, alpha, ('A', 'B'))
    common_ct = fabeo.encrypt(pp, matrix, ('A', 'B'), common_message)
    assert fabeo.decrypt(pp, common_ct, common_key) == common_message
    assert len(native_ct['ct']) == len(common_ct.rows) == 2
    assert len(common_ct.g2_sprime) == 1
    assert len(native_key['sk1']) == len(common_key.sk_by_label) == 2
    # One e(SK2,g2_s), one e(aggregated SKattr,g2_sp), one e(CTrows,g2_r).
    calls = []
    original = backend.pair
    backend.pair = lambda left, right: (calls.append((left, right)) or
                                        original(left, right))
    assert fabeo.decrypt(pp, common_ct, common_key) == common_message
    assert len(calls) == 3
