"""MYABE-08 BLS12-381 algebra core, without protocol authorization.

Inputs marked synthetic are test/direct token sets, not certified credentials.
No method here implements a public eight-algorithm protocol API, TEE or revocation.
"""
from dataclasses import dataclass, field
from time import perf_counter_ns
from typing import Optional, Tuple

from .af import ProtectedPayloadAF
from .crypto import BLS12381Backend
from .encoding import require_bytes, require_uint
from .errors import BackendValidationError, ContractError, Unauthorized
from .lsss import LSSSMatrix, assign_occurrence_ranks, authorized_subset, merge_af_hits
from .types import G1Element, G2Element, GTElement, GroupBinding, Scalar, AFHeader, ProtectedAnonymousFilter

MAX_DEGENERATE_RETRIES = 32


@dataclass(frozen=True)
class AlgebraPublicParameters:
    binding: GroupBinding
    g1: G1Element
    g2: G2Element
    g1_a: G1Element
    g2_a: G2Element
    gt_alpha: GTElement
    c_max: int


@dataclass(frozen=True)
class AlgebraMasterSecret:
    alpha: Scalar = field(repr=False)
    a: Scalar = field(repr=False)


@dataclass(frozen=True)
class UserAlgebraBaseState:
    """Synthetic enclave-side base; deliberately contains no RK."""
    binding: GroupBinding
    mu: Scalar = field(repr=False)
    k0: G2Element = field(repr=False)


@dataclass(frozen=True)
class UserRecoveryScalar:
    """Synthetic DU-side recovery key; contains neither mu nor K0."""
    binding: GroupBinding
    rk: Scalar = field(repr=False)


@dataclass(frozen=True)
class EncryptCoreResult:
    """Public algebra components only; no row tokens, s, y or slot scalars."""
    binding: GroupBinding
    matrix: LSSSMatrix
    c_i: Tuple[G1Element, ...]
    d_j: Tuple[G2Element, ...]
    c: G1Element
    e: GTElement
    c_max: int


@dataclass(frozen=True)
class PublicAlgebraCiphertext:
    """CSP-facing algebra components: E is absent."""
    binding: GroupBinding
    matrix: LSSSMatrix
    c_i: Tuple[G1Element, ...]
    d_j: Tuple[G2Element, ...]
    c: G1Element
    c_max: int


def public_core_view(core: EncryptCoreResult):
    if type(core) is not EncryptCoreResult:
        raise ContractError('EncryptCoreResult required')
    return PublicAlgebraCiphertext(core.binding,core.matrix,core.c_i,core.d_j,core.c,core.c_max)


@dataclass(frozen=True)
class EphemeralAlgebraBundle:
    """Synthetic mathematical output; never a signed TEE authorization."""
    binding: GroupBinding
    tokens: Tuple[bytes, ...]
    k1_q: G2Element
    k_tau_q: Tuple[G1Element, ...]
    t0_q: GTElement


@dataclass(frozen=True)
class TransformAlgebraResult:
    x: G1Element
    y_by_slot: Tuple[Tuple[int, G1Element], ...]
    t_a: GTElement
    candidate_rows: Tuple[int, ...]
    reconstruction_rows: Tuple[int, ...]
    occurrence_slots: Tuple[int, ...]


@dataclass
class AlgebraOperationCounts:
    """Counts explicit algebra-core backend calls; backend internals excluded."""
    g1_exponentiations: int = 0
    g2_exponentiations: int = 0
    gt_exponentiations: int = 0
    g1_multiplications: int = 0
    g2_multiplications: int = 0
    gt_multiplications: int = 0
    gt_divisions: int = 0
    pairing_terms: int = 0
    ell: Optional[int] = None
    candidate_rows: Optional[int] = None
    reconstruction_rows: Optional[int] = None
    c_max: Optional[int] = None
    t_i: Optional[int] = None


@dataclass(frozen=True)
class PairingTermSummary:
    tee_pairing_terms: int
    csp_pairing_terms: int
    system_pairing_terms: int


def pairing_summary(tee: AlgebraOperationCounts, csp: AlgebraOperationCounts):
    return PairingTermSummary(tee.pairing_terms, csp.pairing_terms,
                              tee.pairing_terms+csp.pairing_terms)


def _backend(backend):
    if type(backend) is not BLS12381Backend:
        raise ContractError('verified BLS12381Backend required')


def _draw(backend, source, nonzero):
    value = (backend.random_scalar(binding=backend.binding, nonzero=nonzero)
             if source is None else source(nonzero))
    raw = backend.serialize_scalar(value)
    if nonzero and int.from_bytes(raw, 'big') == 0:
        raise ContractError('nonzero scalar source returned zero')
    return value


def _scalar(backend, value):
    return int.from_bytes(backend.serialize_scalar(value), 'big')


def _g1_mul(backend, point, exponent, counts):
    result=backend.g1_mul(point,exponent)
    if counts is not None: counts.g1_exponentiations+=1
    return result


def _g2_mul(backend, point, exponent, counts):
    result=backend.g2_mul(point,exponent)
    if counts is not None: counts.g2_exponentiations+=1
    return result


def _gt_pow(backend, point, exponent, counts):
    result=backend.gt_pow(point,exponent)
    if counts is not None: counts.gt_exponentiations+=1
    return result


def _g1_add(backend, left, right, counts):
    result=backend.g1_add(left,right)
    if counts is not None: counts.g1_multiplications+=1
    return result


def _g2_add(backend, left, right, counts):
    result=backend.g2_add(left,right)
    if counts is not None: counts.g2_multiplications+=1
    return result


def _gt_mul(backend, left, right, counts):
    result=backend.gt_mul(left,right)
    if counts is not None: counts.gt_multiplications+=1
    return result


def _pair(backend, left, right, counts):
    result=backend.pair(left,right)
    if counts is not None: counts.pairing_terms+=1
    return result


def _validate_public(pp, backend):
    _backend(backend)
    if type(pp) is not AlgebraPublicParameters or pp.binding != backend.binding:
        raise ContractError('algebra PP/backend binding mismatch')
    require_uint(pp.c_max,32,'c_max')
    if pp.c_max == 0:
        raise ContractError('positive c_max required')
    backend.serialize_g1(pp.g1,allow_identity=False)
    backend.serialize_g2(pp.g2,allow_identity=False)
    backend.serialize_g1(pp.g1_a,allow_identity=False)
    backend.serialize_g2(pp.g2_a,allow_identity=False)
    backend.serialize_gt(pp.gt_alpha,allow_identity=False)


def setup_algebra_core(backend: BLS12381Backend, c_max: int, *, scalar_source=None,
                       counts: Optional[AlgebraOperationCounts]=None):
    """Independent nonzero alpha,a; returns algebra PP and separate MSK."""
    _backend(backend)
    require_uint(c_max,32,'c_max')
    if c_max == 0: raise ContractError('positive c_max required')
    alpha,a=_draw(backend,scalar_source,True),_draw(backend,scalar_source,True)
    g1,g2=backend.g1_generator(),backend.g2_generator()
    g1_a=_g1_mul(backend,g1,a,counts)
    g2_a=_g2_mul(backend,g2,a,counts)
    gt_alpha=_gt_pow(backend,_pair(backend,g1,g2,counts),alpha,counts)
    pp=AlgebraPublicParameters(backend.binding,g1,g2,g1_a,g2_a,gt_alpha,c_max)
    _validate_public(pp,backend)
    return pp,AlgebraMasterSecret(alpha,a)


def keygen_algebra_core(pp: AlgebraPublicParameters, msk: AlgebraMasterSecret,
                        backend: BLS12381Backend, *, scalar_source=None,
                        counts: Optional[AlgebraOperationCounts]=None):
    """Returns (enclave base, DU recovery) as distinct trust-domain objects."""
    _validate_public(pp,backend)
    if type(msk) is not AlgebraMasterSecret:
        raise ContractError('algebra MSK required')
    alpha,a=_scalar(backend,msk.alpha),_scalar(backend,msk.a)
    if alpha == 0 or a == 0: raise ContractError('nonzero MSK scalars required')
    order=backend.scalar_order
    for _ in range(MAX_DEGENERATE_RETRIES):
        z,mu=_draw(backend,scalar_source,True),_draw(backend,scalar_source,True)
        exponent=(alpha*_scalar(backend,z)+a*_scalar(backend,mu))%order
        if exponent == 0:
            continue
        k0=_g2_mul(backend,pp.g2,backend.scalar_from_int(exponent),counts)
        backend.serialize_g2(k0,allow_identity=False)
        return (UserAlgebraBaseState(pp.binding,mu,k0),
                UserRecoveryScalar(pp.binding,backend.scalar_inv(z)))
    raise ContractError('nonidentity KeyGen base not found within retry bound')


def encrypt_algebra_core(pp: AlgebraPublicParameters, matrix: LSSSMatrix,
                         policy_tokens, backend: BLS12381Backend, *, scalar_source=None,
                         counts: Optional[AlgebraOperationCounts]=None,
                         component_allocation: str = 'OCCURRENCE'):
    """Synthetic/direct tokenization; ROW is an internal no-reuse ablation."""
    _validate_public(pp,backend)
    if component_allocation not in ('OCCURRENCE', 'ROW'):
        raise ContractError('unknown experimental component allocation')
    if type(matrix) is not LSSSMatrix or matrix.field_order != backend.scalar_order:
        raise ContractError('matrix/field mismatch')
    if type(policy_tokens) not in (tuple,list) or len(policy_tokens)!=matrix.ell:
        raise ContractError('complete ordered policy tokens required')
    ranks=assign_occurrence_ranks(policy_tokens,pp.c_max)
    s=_draw(backend,scalar_source,True)
    vector=(s,)+tuple(_draw(backend,scalar_source,False) for _ in range(matrix.d-1))
    slot_count=pp.c_max if component_allocation=='OCCURRENCE' else matrix.ell
    slot_scalars=tuple(_draw(backend,scalar_source,True) for _ in range(slot_count))
    order=backend.scalar_order
    c_i=[]
    for row_number,(row,token,rank) in enumerate(zip(matrix.rows,policy_tokens,ranks),1):
        lam=sum(value*_scalar(backend,v) for value,v in zip(row,vector))%order
        first=_g1_mul(backend,pp.g1_a,backend.scalar_from_int(lam),counts)
        q=backend.hash_to_g1(token)
        slot=rank if component_allocation=='OCCURRENCE' else row_number
        minus_r=backend.scalar_from_int((-_scalar(backend,slot_scalars[slot-1]))%order)
        mask=_g1_mul(backend,q,minus_r,counts)
        c_i.append(_g1_add(backend,first,mask,counts))
    d_j=tuple(_g2_mul(backend,pp.g2,r,counts) for r in slot_scalars)
    c=_g1_mul(backend,pp.g1,s,counts)
    e=_gt_pow(backend,pp.gt_alpha,s,counts)
    if counts is not None:
        counts.ell=matrix.ell
        counts.c_max=pp.c_max
    return EncryptCoreResult(pp.binding,matrix,tuple(c_i),d_j,c,e,pp.c_max)


def derive_ephemeral_algebra(pp: AlgebraPublicParameters, base: UserAlgebraBaseState,
                             synthetic_tokens, c: G1Element, backend: BLS12381Backend,
                             *, scalar_source=None, counts: Optional[AlgebraOperationCounts]=None,
                             stage_timings_ns=None):
    """Only §5.6 steps 6–7 mathematical core; no authorization decision."""
    _validate_public(pp,backend)
    if type(base) is not UserAlgebraBaseState or base.binding != pp.binding:
        raise ContractError('base state binding mismatch')
    mu=_scalar(backend,base.mu)
    backend.serialize_g2(base.k0,allow_identity=False)
    backend.serialize_g1(c,allow_identity=False)
    if mu == 0: raise ContractError('base mu must be nonzero')
    if type(synthetic_tokens) not in (tuple,list) or not synthetic_tokens:
        raise ContractError('nonempty synthetic token sequence required')
    tokens=tuple(synthetic_tokens)
    for token in tokens: require_bytes(token,'synthetic token',32)
    if len(set(tokens))!=len(tokens): raise ContractError('duplicate synthetic token')
    tokens=tuple(sorted(tokens))
    order=backend.scalar_order
    rerandomization_started=perf_counter_ns() if stage_timings_ns is not None else None
    for _ in range(MAX_DEGENERATE_RETRIES):
        delta=_draw(backend,scalar_source,True)
        mu_q=(mu+_scalar(backend,delta))%order
        if mu_q == 0: continue
        k0_q=_g2_add(backend,base.k0,_g2_mul(backend,pp.g2_a,delta,counts),counts)
        try:
            backend.serialize_g2(k0_q,allow_identity=False)
        except BackendValidationError:
            continue
        mu_q_scalar=backend.scalar_from_int(mu_q)
        k1=_g2_mul(backend,pp.g2,mu_q_scalar,counts)
        components=tuple(_g1_mul(backend,backend.hash_to_g1(token),mu_q_scalar,counts)
                         for token in tokens)
        if stage_timings_ns is not None:
            stage_timings_ns['rerandomization_ns']=perf_counter_ns()-rerandomization_started
            pairing_started=perf_counter_ns()
        t0=_pair(backend,c,k0_q,counts)
        if stage_timings_ns is not None:
            stage_timings_ns['t0_pairing_ns']=perf_counter_ns()-pairing_started
        return EphemeralAlgebraBundle(pp.binding,tokens,k1,components,t0)
    raise ContractError('nondegenerate ephemeral state not found within retry bound')


def transform_algebra_core(pp: AlgebraPublicParameters, ct: EncryptCoreResult,
                           bundle: EphemeralAlgebraBundle, index: ProtectedAnonymousFilter,
                           header: AFHeader, ctx_af: bytes, backend: BLS12381Backend, *,
                           counts: Optional[AlgebraOperationCounts]=None,
                           stage_timings_ns=None,
                           component_allocation: str = 'OCCURRENCE'):
    """Synthetic AF/LSSS/attribute math; no cap/publication verification."""
    _validate_public(pp,backend)
    if component_allocation not in ('OCCURRENCE', 'ROW'):
        raise ContractError('unknown experimental component allocation')
    expected_slots=pp.c_max if component_allocation=='OCCURRENCE' else ct.matrix.ell
    if (type(ct) not in (EncryptCoreResult,PublicAlgebraCiphertext) or ct.binding != pp.binding or
            type(bundle) is not EphemeralAlgebraBundle or bundle.binding != pp.binding or
            ct.c_max != pp.c_max or len(ct.c_i) != ct.matrix.ell or
            len(ct.d_j) != expected_slots or len(bundle.tokens) != len(bundle.k_tau_q)):
        raise ContractError('algebra component binding/shape mismatch')
    if header.ell != ct.matrix.ell or header.parameters.c_max != pp.c_max or header.sys_id != pp.binding.sys_id:
        raise ContractError('AF/algebra shape mismatch')
    if (type(bundle.tokens) is not tuple or type(bundle.k_tau_q) is not tuple
            or not bundle.tokens or tuple(sorted(set(bundle.tokens))) != bundle.tokens):
        raise ContractError('synthetic bundle tokens must be sorted and unique')
    for token in bundle.tokens: require_bytes(token,'synthetic token',32)
    if ct.matrix.field_order != backend.scalar_order:
        raise ContractError('ciphertext matrix field mismatch')
    backend.serialize_g1(ct.c,allow_identity=False)
    if type(ct) is EncryptCoreResult:
        backend.serialize_gt(ct.e,allow_identity=False)
    backend.serialize_g2(bundle.k1_q,allow_identity=False)
    backend.serialize_gt(bundle.t0_q)
    for element in ct.c_i: backend.serialize_g1(element)
    for element in ct.d_j: backend.serialize_g2(element,allow_identity=False)
    for element in bundle.k_tau_q: backend.serialize_g1(element,allow_identity=False)
    query_started=perf_counter_ns() if stage_timings_ns is not None else None
    from .metrics import AFMetrics
    af_metrics=AFMetrics() if stage_timings_ns is not None else None
    hits=[]
    af=ProtectedPayloadAF()
    for token in bundle.tokens:
        result=af.query(index,token,header=header,ctx_af=ctx_af,
                        metrics=af_metrics)
        if result.hit: hits.append((token,result.rows))
    J,phi=merge_af_hits(tuple(hits))
    if stage_timings_ns is not None:
        stage_timings_ns['af_query_ns']=perf_counter_ns()-query_started
        stage_timings_ns['af_decoded_payload_count']=af_metrics.decoded_payloads or 0
        subset_started=perf_counter_ns()
    witness={w.row:w for w in phi}
    solution=authorized_subset(ct.matrix,J,backend,witnesses=phi)
    if stage_timings_ns is not None:
        stage_timings_ns['authorized_subset_ns']=perf_counter_ns()-subset_started
        ta_started=perf_counter_ns()
    terms=solution.terms
    if not terms or any(t.row not in witness for t in terms):
        raise ContractError('invalid reconstruction witness')
    c_i_slots=(solution.occurrence_slots if component_allocation=='OCCURRENCE'
               else tuple(sorted(term.row for term in terms)))
    if not 1<=len(c_i_slots)<=min(len(terms),expected_slots):
        raise ContractError('invalid occurrence slot count')
    # Recheck reconstruction before any attribute pairing.
    target=tuple(sum(ct.matrix.rows[term.row-1][j]*_scalar(backend,term.coefficient)
                     for term in terms) % backend.scalar_order
                 for j in range(ct.matrix.d))
    if target!=(1,)+(0,)*(ct.matrix.d-1):
        raise ContractError('reconstruction verification failed')
    component_by_token=dict(zip(bundle.tokens,bundle.k_tau_q))
    x=None
    y={}
    for term in terms:
        coeff=term.coefficient
        row=term.row
        token=witness[row].token
        slot=(witness[row].occurrence_rank if component_allocation=='OCCURRENCE'
              else row)
        part_x=_g1_mul(backend,ct.c_i[row-1],coeff,counts)
        part_y=_g1_mul(backend,component_by_token[token],coeff,counts)
        x=part_x if x is None else _g1_add(backend,x,part_x,counts)
        y[slot]=part_y if slot not in y else _g1_add(backend,y[slot],part_y,counts)
    ta=_pair(backend,x,bundle.k1_q,counts)
    for slot in sorted(y):
        ta=_gt_mul(backend,ta,_pair(backend,y[slot],ct.d_j[slot-1],counts),counts)
    if stage_timings_ns is not None:
        stage_timings_ns['t_a_ns']=perf_counter_ns()-ta_started
    if counts is not None:
        counts.ell=ct.matrix.ell
        counts.candidate_rows=len(J)
        counts.reconstruction_rows=len(terms)
        counts.c_max=pp.c_max
        counts.t_i=len(c_i_slots)
    return TransformAlgebraResult(x,tuple(sorted(y.items())),ta,J,
                                  tuple(t.row for t in terms),c_i_slots)


def finaldec_algebra_core(t0_q: GTElement, t_a: GTElement,
                          recovery: UserRecoveryScalar, backend: BLS12381Backend, *,
                          counts: Optional[AlgebraOperationCounts]=None):
    """Compute (T0/T_A)^RK; no DEM/header/cap checks or pairing."""
    _backend(backend)
    if type(recovery) is not UserRecoveryScalar or recovery.binding!=backend.binding:
        raise ContractError('recovery/backend binding mismatch')
    if _scalar(backend,recovery.rk)==0:
        raise ContractError('zero recovery scalar forbidden')
    quotient=backend.gt_div(t0_q,t_a)
    if counts is not None: counts.gt_divisions+=1
    recovered=_gt_pow(backend,quotient,recovery.rk,counts)
    return quotient,recovered
