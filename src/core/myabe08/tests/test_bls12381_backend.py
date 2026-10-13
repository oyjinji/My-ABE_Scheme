"""Real backend correctness, not MYABE algebra or an ABE security proof."""
import pytest
from py_ecc import optimized_bls12_381 as bls
from py_ecc.bls.point_compression import compress_G1, compress_G2, decompress_G1, decompress_G2
from py_ecc.bls.hash_to_curve import map_to_curve_G1, map_to_curve_G2

from core.myabe08.crypto import BLS12381Backend
from core.myabe08.errors import BackendValidationError
from core.myabe08.types import G1Element, G2Element, GTElement, Scalar


@pytest.fixture(scope='module')
def backend():
    return BLS12381Backend(b'MYABE08-BACKEND-TEST')


@pytest.fixture(scope='module')
def target(backend):
    return backend.pair(backend.g1_generator(),backend.g2_generator())


def test_generators_validity_and_standard_compression(backend):
    g1,g2=backend.g1_generator(),backend.g2_generator()
    raw1,raw2=backend.serialize_g1(g1,allow_identity=False),backend.serialize_g2(g2,allow_identity=False)
    assert len(raw1)==48 and len(raw2)==96
    p=decompress_G1(int.from_bytes(raw1,'big'))
    q=decompress_G2((int.from_bytes(raw2[:48],'big'),int.from_bytes(raw2[48:],'big')))
    assert bls.eq(p,bls.G1) and bls.eq(q,bls.G2)
    assert bls.is_on_curve(p,bls.b) and bls.is_on_curve(q,bls.b2)
    assert bls.is_inf(bls.multiply(p,bls.curve_order))
    assert bls.is_inf(bls.multiply(q,bls.curve_order))
    assert backend.deserialize_g1(raw1,binding=backend.binding)==g1
    assert backend.deserialize_g2(raw2,binding=backend.binding)==g2


def test_scalar_field_operations_and_roundtrip(backend):
    x=backend.scalar_random_nonzero()
    one=backend.scalar_from_int(1)
    assert backend.scalar_mul(x,backend.scalar_inv(x))==one
    assert backend.scalar_add(backend.scalar_from_int(backend.scalar_order-1),one)==backend.scalar_from_int(0)
    assert backend.deserialize_scalar(backend.serialize_scalar(x),binding=backend.binding)==x
    assert len(backend.serialize_scalar(x))==32
    with pytest.raises(BackendValidationError):backend.scalar_inv(backend.scalar_from_int(0))
    with pytest.raises(BackendValidationError):backend.scalar_from_int(True)
    with pytest.raises(BackendValidationError):backend.deserialize_scalar(bytes(32),binding=backend.binding,allow_zero=False)


def test_real_pairing_bilinearity_random_nonzero_scalars(backend,target):
    x,y=backend.scalar_random_nonzero(),backend.scalar_random_nonzero()
    left=backend.pair(backend.g1_mul(backend.g1_generator(),x),backend.g2_mul(backend.g2_generator(),y))
    right=backend.gt_pow(target,backend.scalar_mul(x,y))
    assert left==right


def test_group_addition_and_direction(backend):
    one,two=backend.scalar_from_int(1),backend.scalar_from_int(2)
    assert backend.g1_add(backend.g1_generator(),backend.g1_generator())==backend.g1_mul(backend.g1_generator(),two)
    assert backend.g2_add(backend.g2_generator(),backend.g2_generator())==backend.g2_mul(backend.g2_generator(),two)
    with pytest.raises(BackendValidationError):backend.pair(backend.g2_generator(),backend.g1_generator())
    with pytest.raises(BackendValidationError):backend.g1_mul(backend.g2_generator(),one)


def test_gt_canonical_basis_roundtrip(backend,target):
    data=backend.serialize_gt(target)
    assert len(data)==576
    direct=bls.pairing(bls.G2,bls.G1)
    assert data==b''.join(int(c).to_bytes(48,'big') for c in direct.coeffs)
    assert backend.deserialize_gt(data,binding=backend.binding)==target
    assert backend.gt_mul(target,target)==backend.gt_pow(target,backend.scalar_from_int(2))


def test_identity_allowed_or_rejected_by_explicit_policy(backend):
    zero=backend.scalar_from_int(0)
    for group in ('g1','g2'):
        point=getattr(backend,group+'_mul')(getattr(backend,group+'_generator')(),zero)
        raw=getattr(backend,'serialize_'+group)(point)
        assert getattr(backend,'deserialize_'+group)(raw,binding=backend.binding)==point
        with pytest.raises(BackendValidationError):
            getattr(backend,'deserialize_'+group)(raw,binding=backend.binding,allow_identity=False)
    identity=(1).to_bytes(48,'big')+bytes(528)
    assert backend.deserialize_gt(identity,binding=backend.binding).encoded==identity
    with pytest.raises(BackendValidationError):
        backend.deserialize_gt(identity,binding=backend.binding,allow_identity=False)


def test_h0_real_hash_to_curve_subgroup_and_serialization(backend):
    p=backend.hash_to_g1(b'a'*32)
    assert p==backend.hash_to_g1(b'a'*32)
    assert p!=backend.hash_to_g1(b'b'*32)  # sample inequality, not collision proof
    point=decompress_G1(int.from_bytes(p.encoded,'big'))
    assert not bls.is_inf(point) and bls.is_on_curve(point,bls.b)
    assert bls.is_inf(bls.multiply(point,bls.curve_order))
    assert backend.deserialize_g1(p.encoded,binding=backend.binding,allow_identity=False)==p


@pytest.mark.parametrize('kind,width', [('scalar',32),('g1',48),('g2',96),('gt',576)])
def test_wrong_lengths_rejected(backend,kind,width):
    for raw in (bytes(width-1),bytes(width+1),bytearray(width)):
        with pytest.raises(BackendValidationError):
            getattr(backend,'deserialize_'+kind)(raw,binding=backend.binding)


def test_scalar_and_gt_field_range_and_gt_subgroup_rejection(backend):
    with pytest.raises(BackendValidationError):
        backend.deserialize_scalar(bls.curve_order.to_bytes(32,'big'),binding=backend.binding)
    bads=[bytes(576),bls.field_modulus.to_bytes(48,'big')+bytes(528),(2).to_bytes(48,'big')+bytes(528)]
    for raw in bads:
        with pytest.raises(BackendValidationError):backend.deserialize_gt(raw,binding=backend.binding)


def test_valid_curve_points_outside_subgroups_are_rejected(backend):
    p=map_to_curve_G1(bls.FQ(1))
    q=map_to_curve_G2(bls.FQ2([1,2]))
    assert bls.is_on_curve(p,bls.b) and bls.is_on_curve(q,bls.b2)
    assert not bls.is_inf(bls.multiply(p,bls.curve_order))
    assert not bls.is_inf(bls.multiply(q,bls.curve_order))
    raw1=int(compress_G1(p)).to_bytes(48,'big')
    a,b=compress_G2(q);raw2=int(a).to_bytes(48,'big')+int(b).to_bytes(48,'big')
    with pytest.raises(BackendValidationError):backend.deserialize_g1(raw1,binding=backend.binding)
    with pytest.raises(BackendValidationError):backend.deserialize_g2(raw2,binding=backend.binding)


def test_malformed_points_and_direct_dto_forgery_rejected(backend):
    for kind,width in [('g1',48),('g2',96)]:
        for bad in (bytes(width),b'\xff'*width):
            with pytest.raises(BackendValidationError):getattr(backend,'deserialize_'+kind)(bad,binding=backend.binding)
    # Constructing a Phase 1 DTO must never bypass the real operation boundary.
    with pytest.raises(BackendValidationError):backend.pair(G1Element(backend.binding,bytes(48)),backend.g2_generator())
    with pytest.raises(BackendValidationError):backend.scalar_add(Scalar(backend.binding,b'bad'),backend.scalar_from_int(1))


def test_compressed_coordinates_not_on_curve_rejected(backend):
    # Valid compression flag/width, but no curve y exists at these coordinates.
    g1_bad=((1<<383)|1).to_bytes(48,'big')
    g2_bad=((1<<383)|2).to_bytes(48,'big')+bytes(48)
    with pytest.raises(BackendValidationError):backend.deserialize_g1(g1_bad,binding=backend.binding)
    with pytest.raises(BackendValidationError):backend.deserialize_g2(g2_bad,binding=backend.binding)
