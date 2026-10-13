"""Explicit MYABE08 V1 public-object transport; no object graph serializer."""

from ..af import encode_af_metadata
from ..algebra import AlgebraPublicParameters
from ..capability import authorization_bytes, bundle_bytes
from ..credential import credential_bytes, decode_private_ingress
from ..encoding import UInt32, UInt64, StructuredRecord, decode, encode, require_bytes
from ..errors import ContractError
from ..profile import (MYABE08_ENCODING_V1, MYABE08_ROW_ABLATION_ENCODING_V1,
                       SECURITY_PROFILE_BLS12_381,
                       SGX_DEBUG_GRAMINE_V1, EMULATED_TEE_PROFILE)
from ..types import (AFHeader, AFMetadata, AFParameters, AuthorizationBundle,
    Ciphertext, CiphertextHeader, Credential, EphemeralTokenComponent, KEMDEMInfo,
    NamespaceCertificate, PolicyContext, ProfileMetadata, ProtectedAnonymousFilter,
    SignedCapability, TEEAuthorization, Validity)


def _u32(value):
    if type(value) is not UInt32: raise ContractError('uint32 wire field required')
    return value.value


def _u64(value):
    if type(value) is not UInt64: raise ContractError('uint64 wire field required')
    return value.value


def _tuple(value,size,label):
    if type(value) is not tuple or len(value)!=size:
        raise ContractError(label+' wire shape mismatch')
    return value


def encode_public_parameters(pp,backend):
    if type(pp) is not AlgebraPublicParameters or pp.binding!=backend.binding:
        raise ContractError('algebra public parameters required')
    return encode(('MYABE08-SGX-PP-V1',pp.binding.sys_id,
        backend.serialize_g1(pp.g1,allow_identity=False),
        backend.serialize_g2(pp.g2,allow_identity=False),
        backend.serialize_g1(pp.g1_a,allow_identity=False),
        backend.serialize_g2(pp.g2_a,allow_identity=False),
        backend.serialize_gt(pp.gt_alpha),UInt32(pp.c_max)))


def decode_public_parameters(raw,backend):
    o=_tuple(decode(raw),8,'PP')
    if o[0]!='MYABE08-SGX-PP-V1' or o[1]!=backend.binding.sys_id:
        raise ContractError('PP profile/SysID mismatch')
    pp=AlgebraPublicParameters(backend.binding,
        backend.deserialize_g1(o[2],binding=backend.binding,allow_identity=False),
        backend.deserialize_g2(o[3],binding=backend.binding,allow_identity=False),
        backend.deserialize_g1(o[4],binding=backend.binding,allow_identity=False),
        backend.deserialize_g2(o[5],binding=backend.binding,allow_identity=False),
        backend.deserialize_gt(o[6],binding=backend.binding),_u32(o[7]))
    if encode_public_parameters(pp,backend)!=raw: raise ContractError('noncanonical PP')
    return pp


def encode_certificate(cert):
    if type(cert) is not NamespaceCertificate: raise ContractError('certificate required')
    return (cert.sys_id,cert.namespace,cert.publisher_public_key,
            UInt64(cert.validity.not_before),UInt64(cert.validity.not_after),
            UInt64(cert.cert_version),cert.kgc_signature)


def decode_certificate(value):
    o=_tuple(value,7,'certificate')
    return NamespaceCertificate(o[0],o[1],o[2],Validity(_u64(o[3]),_u64(o[4])),
                                o[6],_u64(o[5]))


def encode_context(context):
    if type(context) is not PolicyContext: raise ContractError('context required')
    return (context.sys_id,context.policy_context_id,UInt64(context.policy_version),
            context.ctx_priv)


def decode_context(value):
    o=_tuple(value,4,'context')
    return PolicyContext(o[0],o[1],_u64(o[2]),o[3])


def encode_publication(ct,backend):
    if type(ct) is not Ciphertext: raise ContractError('Ciphertext required')
    h=ct.header;a=h.af_header;m=ct.anonymous_filter.metadata
    encoding=h.kem_dem_info.profile.encoding_version
    if encoding==MYABE08_ENCODING_V1:
        magic='MYABE08-CT-V1'
    elif (encoding==MYABE08_ROW_ABLATION_ENCODING_V1 and
          h.kem_dem_info.profile.tee_profile_id==EMULATED_TEE_PROFILE):
        magic='MYABE08-CT-ROW-ABLATION-TEST-V1'
    else:
        raise ContractError('unsupported CT allocation encoding')
    ah=(a.sys_id,a.ctx_priv,a.matrix_digest,UInt32(a.ell),
        UInt32(a.distinct_tokens),UInt32(a.parameters.c_max))
    hh=(h.data_id,backend.serialize_g1(h.c,allow_identity=False),UInt32(h.c_max),
        h.core_components_digest,h.af_metadata_digest,h.filter_digest,
        h.kem_dem_info.profile.tee_profile_id)
    matrix=tuple(tuple(backend.serialize_scalar(backend.scalar_from_int(
                    value%backend.scalar_order)) for value in row) for row in ct.matrix)
    return encode((magic,encode_certificate(ct.publisher_certificate),
        encode_context(h.context),ah,encode_af_metadata(m),hh,
        tuple(backend.serialize_g1(c) for c in ct.row_components),
        tuple(backend.serialize_g2(d,allow_identity=False) for d in ct.occurrence_components),
        matrix,ct.anonymous_filter.slots,ct.dem_nonce,ct.encrypted_message,
        ct.publication_signature))


def _decode_af_metadata(raw):
    record=decode(raw)
    names=('profile_id','encoding_profile_id','sys_id','ell','u','c_max',
           'segment_length','m_af','seed_af','slot_payload_bytes')
    if (type(record) is not StructuredRecord or record.schema!='MYABE08.AFMetadataV1'
            or tuple(k for k,_ in record.fields)!=names):
        raise ContractError('AF metadata schema mismatch')
    v=tuple(x for _,x in record.fields)
    meta=AFMetadata(v[0],v[1],v[2],_u32(v[3]),_u32(v[4]),_u32(v[5]),
                    _u64(v[6]),_u64(v[7]),v[8],_u64(v[9]))
    if encode_af_metadata(meta)!=raw: raise ContractError('AF metadata noncanonical')
    return meta


def decode_publication(raw,backend,*,expected_profile=SGX_DEBUG_GRAMINE_V1):
    o=_tuple(decode(raw),13,'ciphertext')
    if o[0]=='MYABE08-CT-V1':
        encoding=MYABE08_ENCODING_V1
    elif o[0]=='MYABE08-CT-ROW-ABLATION-TEST-V1' and expected_profile==EMULATED_TEE_PROFILE:
        encoding=MYABE08_ROW_ABLATION_ENCODING_V1
    else:
        raise ContractError('CT wire version mismatch')
    if expected_profile not in (SGX_DEBUG_GRAMINE_V1,EMULATED_TEE_PROFILE):
        raise ContractError('unsupported CT profile')
    cert=decode_certificate(o[1]);ctx=decode_context(o[2]);ah=_tuple(o[3],6,'AF header')
    afh=AFHeader(ah[0],ah[1],ah[2],_u32(ah[3]),_u32(ah[4]),AFParameters(_u32(ah[5])))
    meta=_decode_af_metadata(o[4]);hh=_tuple(o[5],7,'CT header')
    if hh[6]!=expected_profile: raise ContractError('cross-profile CT rejected')
    info=KEMDEMInfo(ProfileMetadata(SECURITY_PROFILE_BLS12_381,hh[6],
                                    encoding))
    header=CiphertextHeader(afh,ctx,hh[0],backend.deserialize_g1(hh[1],
        binding=backend.binding,allow_identity=False),_u32(hh[2]),hh[3],hh[4],hh[5],info)
    if (type(o[6]) is not tuple or type(o[7]) is not tuple or
            type(o[8]) is not tuple or type(o[9]) is not tuple):
        raise ContractError('CT array shapes required')
    rows=tuple(backend.deserialize_g1(x,binding=backend.binding) for x in o[6])
    slots=tuple(backend.deserialize_g2(x,binding=backend.binding,
                                        allow_identity=False) for x in o[7])
    matrix=tuple(tuple(int.from_bytes(require_scalar(x,backend),'big') for x in row)
                 for row in o[8])
    ct=Ciphertext(rows,slots,matrix,ProtectedAnonymousFilter(o[9],meta),
                  o[10],o[11],header,o[12],cert)
    if (ctx.sys_id!=backend.binding.sys_id or afh.sys_id!=backend.binding.sys_id or
            meta.sys_id!=backend.binding.sys_id or cert.sys_id!=backend.binding.sys_id or
            len(rows)!=afh.ell or len(slots)!=(afh.parameters.c_max if
                encoding==MYABE08_ENCODING_V1 else afh.ell) or
            len(matrix)!=afh.ell or not matrix or not matrix[0] or
            any(len(row)!=len(matrix[0]) for row in matrix) or
            len(o[9])!=meta.m_af):
        raise ContractError('CT SysID or shape mismatch')
    if encode_publication(ct,backend)!=raw: raise ContractError('noncanonical CT wire')
    return ct


def require_scalar(raw,backend):
    backend.deserialize_scalar(raw,binding=backend.binding)
    return raw


def encode_registration(credential,base,backend):
    if type(credential) is not Credential: raise ContractError('Credential required')
    return encode(('MYABE08-SGX-REG-V1',credential_bytes(credential),
                   credential.signature,backend.serialize_scalar(base.mu),
                   backend.serialize_g2(base.k0,allow_identity=False)))


def decode_registration(raw,backend):
    o=_tuple(decode(raw),5,'registration')
    if o[0]!='MYABE08-SGX-REG-V1': raise ContractError('registration version')
    private=encode(('MYABE-PRIVATE-INGRESS',o[1],o[2],b'opaque',b'proof'))
    credential,_,_=decode_private_ingress(private)
    mu=backend.deserialize_scalar(o[3],binding=backend.binding,allow_zero=False)
    k0=backend.deserialize_g2(o[4],binding=backend.binding,allow_identity=False)
    from ..algebra import UserAlgebraBaseState
    base=UserAlgebraBaseState(backend.binding,mu,k0)
    if encode_registration(credential,base,backend)!=raw:
        raise ContractError('noncanonical registration')
    return credential,base


def decode_authorization(raw,backend):
    o=_tuple(decode(raw),4,'Auth')
    if o[0]!='MYABE-AUTH-ENVELOPE': raise ContractError('Auth schema mismatch')
    bundle_wire=o[1];b=_tuple(decode(bundle_wire),4,'bundle')
    if b[0]!='MYABE-BUNDLE' or type(b[1]) is not tuple:
        raise ContractError('bundle schema mismatch')
    items=tuple(EphemeralTokenComponent(t,backend.deserialize_g1(p,
        binding=backend.binding,allow_identity=False)) for t,p in b[1])
    bundle=AuthorizationBundle(items,backend.deserialize_g2(b[2],
        binding=backend.binding,allow_identity=False),
        backend.deserialize_gt(b[3],binding=backend.binding))
    if bundle_bytes(bundle,backend)!=bundle_wire: raise ContractError('bundle noncanonical')
    f=_tuple(o[2],7,'capability')
    cap=SignedCapability(f[0],f[1],f[2],_u64(f[3]),f[4],_u64(f[5]),f[6],o[3])
    auth=TEEAuthorization(bundle,cap)
    if cap.sys_id!=backend.binding.sys_id:
        raise ContractError('Auth SysID mismatch')
    if authorization_bytes(auth,backend)!=raw: raise ContractError('Auth noncanonical')
    return auth
