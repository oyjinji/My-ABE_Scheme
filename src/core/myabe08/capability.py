"""Signed B_q binding and CSP one-time consumption; no hardware secrecy claim."""
import hashlib

from .encoding import UInt64,encode,require_bytes,require_uint
from .errors import ContractError,ProtocolRejectedError
from .publication import header_digest,verify_publication
from .signing import sign_canonical,verify_canonical
from .types import (AuthorizationBundle,EphemeralTokenComponent,SignedCapability,
                    TEEAuthorization)


def bundle_bytes(bundle,backend):
    if type(bundle) is not AuthorizationBundle or type(bundle.items) is not tuple or not bundle.items:
        raise ContractError('ordered nonempty AuthorizationBundle required')
    tokens=tuple(item.token for item in bundle.items)
    if tokens!=tuple(sorted(set(tokens))):
        raise ContractError('B_q token order/uniqueness mismatch')
    records=[]
    for item in bundle.items:
        if type(item) is not EphemeralTokenComponent: raise ContractError('B_q record malformed')
        require_bytes(item.token,'token',32)
        records.append((item.token,backend.serialize_g1(item.k_tau_q,allow_identity=False)))
    return encode(('MYABE-BUNDLE',tuple(records),
                   backend.serialize_g2(bundle.k1_q,allow_identity=False),
                   backend.serialize_gt(bundle.t0_q)))


def bundle_digest(bundle,backend):
    return hashlib.sha256(bundle_bytes(bundle,backend)).digest()


def from_ephemeral(ephemeral):
    from .algebra import EphemeralAlgebraBundle
    if type(ephemeral) is not EphemeralAlgebraBundle:
        raise ContractError('synthetic ephemeral algebra bundle required')
    return AuthorizationBundle(tuple(EphemeralTokenComponent(t,k) for t,k in
                                     zip(ephemeral.tokens,ephemeral.k_tau_q)),
                               ephemeral.k1_q,ephemeral.t0_q)


def capability_fields(cap):
    if type(cap) is not SignedCapability: raise ContractError('SignedCapability required')
    require_bytes(cap.sys_id,'SysID')
    require_bytes(cap.header_digest,'header digest',32)
    require_bytes(cap.ctx_priv,'ctx_priv',32)
    require_bytes(cap.bundle_digest,'bundle digest',32)
    require_bytes(cap.request_nonce,'request nonce')
    if len(cap.request_nonce)<32: raise ContractError('nonce requires 32 bytes')
    require_uint(cap.rev_version,64,'rev_version')
    require_uint(cap.expiry,64,'expiry')
    return (cap.sys_id,cap.header_digest,cap.ctx_priv,UInt64(cap.rev_version),
            cap.request_nonce,UInt64(cap.expiry),cap.bundle_digest)


def sign_capability(cap_private,sys_id,header_hash,ctx_priv,rev_version,
                    request_nonce,expiry,bundle,backend):
    unsigned=SignedCapability(sys_id,header_hash,ctx_priv,rev_version,
                              request_nonce,expiry,bundle_digest(bundle,backend),b'')
    signature=sign_canonical(cap_private,'MYABE-AUTH',*capability_fields(unsigned))
    return TEEAuthorization(bundle,SignedCapability(sys_id,header_hash,ctx_priv,
                            rev_version,request_nonce,expiry,unsigned.bundle_digest,signature))


def verify_capability(auth,ct,backend,cap_public,clock,*,metrics=None):
    if clock is None: raise ProtocolRejectedError('clock unavailable')
    if type(auth) is not TEEAuthorization: raise ContractError('TEEAuthorization required')
    cap=auth.capability
    fields=capability_fields(cap)
    if (cap.sys_id!=backend.binding.sys_id or
        cap.header_digest!=header_digest(ct.header,backend) or
        cap.ctx_priv!=ct.header.context.ctx_priv or
        cap.bundle_digest!=bundle_digest(auth.bundle,backend)):
        raise ProtocolRejectedError('capability binding mismatch')
    verify_canonical(cap_public,cap.signature,'MYABE-AUTH',*fields)
    now=clock.now()
    if type(now) is not int or now>=cap.expiry: raise ProtocolRejectedError('capability expired')
    if metrics is not None: metrics.cap_verifications+=1
    return auth


def verify_and_consume(auth,ct,backend,cap_public,kgc_public,namespace,clock,csp_state,
                       *,metrics=None):
    if csp_state is None: raise ProtocolRejectedError('CSP consume state unavailable')
    verify_publication(ct,backend,kgc_public,namespace,clock)
    verify_capability(auth,ct,backend,cap_public,clock,metrics=metrics)
    csp_state.consume_once(auth.capability.sys_id,auth.capability.request_nonce)
    if metrics is not None: metrics.request_consumptions+=1
    return auth


def authorization_bytes(auth,backend):
    if type(auth) is not TEEAuthorization: raise ContractError('TEEAuthorization required')
    return encode(('MYABE-AUTH-ENVELOPE',bundle_bytes(auth.bundle,backend),
                   capability_fields(auth.capability),auth.capability.signature))


def csp_transform_verified(auth,ct,algebra_pp,backend,cap_public,kgc_public,
                           namespace,clock,csp_state,*,counts=None,metrics=None,
                           stage_timings_ns=None):
    from .algebra import transform_algebra_core
    from .af import compute_ctx_af
    from .publication import public_algebra_from_ciphertext
    from .profile import MYABE08_ENCODING_V1, MYABE08_ROW_ABLATION_ENCODING_V1
    verify_and_consume(auth,ct,backend,cap_public,kgc_public,namespace,clock,csp_state,
                       metrics=metrics)
    encoding=ct.header.kem_dem_info.profile.encoding_version
    if encoding==MYABE08_ENCODING_V1:
        allocation='OCCURRENCE'
    elif encoding==MYABE08_ROW_ABLATION_ENCODING_V1:
        allocation='ROW'
    else:
        raise ContractError('unsupported algebra allocation encoding')
    return transform_algebra_core(algebra_pp,public_algebra_from_ciphertext(ct,backend),
        _ephemeral_view(auth,backend),ct.anonymous_filter,ct.header.af_header,
        compute_ctx_af(ct.header.af_header),backend,counts=counts,
        stage_timings_ns=stage_timings_ns,
        component_allocation=allocation)


def _ephemeral_view(auth,backend):
    from .algebra import EphemeralAlgebraBundle
    bundle=auth.bundle
    return EphemeralAlgebraBundle(backend.binding,
        tuple(item.token for item in bundle.items),bundle.k1_q,
        tuple(item.k_tau_q for item in bundle.items),bundle.t0_q)
