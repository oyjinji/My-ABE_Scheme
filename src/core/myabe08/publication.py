"""Canonical publication envelope and DO certificate, without policy labels."""
import hashlib
from time import perf_counter_ns

from .af import compute_ctx_af, encode_af_metadata, header_record, validate_metadata
from .crypto import dem_encrypt
from .encoding import (FixedScalarBytes, StructuredRecord, UInt32, UInt64,
                       encode, require_bytes, require_uint)
from .errors import ContractError, ProtocolRejectedError
from .profile import (EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1,
                      MYABE08_ENCODING_V1, MYABE08_ROW_ABLATION_ENCODING_V1,
                      SECURITY_PROFILE_BLS12_381)
from .signing import public_key_bytes, sign_canonical, verify_canonical
from .types import (AFHeader, AFParameters, Ciphertext, CiphertextHeader,
                    KEMDEMInfo, NamespaceCertificate, PolicyContext,
                    ProfileMetadata, Validity)


def indexed_bytes(values):
    if type(values) is not tuple:
        raise ContractError('indexed list must be tuple')
    result=[]
    for index,value in enumerate(values,1):
        require_uint(index,32,'index')
        require_bytes(value,'indexed item')
        result.append((UInt32(index),value))
    return tuple(result)


def matrix_bytes(matrix,backend):
    from .lsss import LSSSMatrix
    if type(matrix) is not LSSSMatrix or matrix.field_order!=backend.scalar_order:
        raise ContractError('matrix field mismatch')
    rows=tuple((UInt32(i),tuple(FixedScalarBytes(backend.serialize_scalar(
                     backend.scalar_from_int(value%backend.scalar_order))) for value in row))
               for i,row in enumerate(matrix.rows,1))
    return encode(('MYABE-MATRIX',UInt32(matrix.ell),UInt32(matrix.d),rows))


def matrix_digest(matrix,backend):
    return hashlib.sha256(matrix_bytes(matrix,backend)).digest()


def core_components_digest(c_i,d_j,backend):
    return hashlib.sha256(encode(('MYABE-CORE-COMPONENTS',
        indexed_bytes(tuple(backend.serialize_g1(c) for c in c_i)),
        indexed_bytes(tuple(backend.serialize_g2(d,allow_identity=False) for d in d_j))))).digest()


def filter_digest(index):
    validate_metadata(index.metadata)
    if type(index.slots) is not tuple or len(index.slots)!=index.metadata.m_af:
        raise ContractError('filter slot count mismatch')
    for slot in index.slots: require_bytes(slot,'AF slot',index.metadata.slot_payload_bytes)
    return hashlib.sha256(encode(('MYABE-FILTER',encode_af_metadata(index.metadata),
                                  indexed_bytes(index.slots)))).digest()


def af_metadata_digest(index):
    return hashlib.sha256(encode(('MYABE-AF-METADATA',encode_af_metadata(index.metadata)))).digest()


def make_af_header(matrix,tokens,context,c_max,backend):
    if type(context) is not PolicyContext or context.sys_id!=backend.binding.sys_id:
        raise ContractError('policy context binding mismatch')
    if len(tokens)!=matrix.ell: raise ContractError('token/row count mismatch')
    return AFHeader(context.sys_id,context.ctx_priv,matrix_digest(matrix,backend),
                    matrix.ell,len(set(tokens)),AFParameters(c_max))


def _validity_fields(validity):
    if type(validity) is not Validity: raise ContractError('Validity required')
    return (UInt64(validity.not_before),UInt64(validity.not_after))


def cert_fields(cert):
    if type(cert) is not NamespaceCertificate: raise ContractError('DO certificate required')
    require_bytes(cert.sys_id,'SysID')
    require_bytes(cert.publisher_public_key,'DO public key',32)
    if type(cert.namespace) is not str or not cert.namespace:
        raise ContractError('namespace required')
    require_uint(cert.cert_version,64,'DO cert version')
    if cert.cert_version==0: raise ContractError('positive DO cert version required')
    return (cert.sys_id,cert.namespace,cert.publisher_public_key,
            _validity_fields(cert.validity),UInt64(cert.cert_version))


def issue_do_certificate(kgc_private,sys_id,namespace,do_public,validity,version=1):
    cert=NamespaceCertificate(sys_id,namespace,do_public,validity,b'',version)
    signature=sign_canonical(kgc_private,'MYABE-DO-CERT',*cert_fields(cert))
    return NamespaceCertificate(sys_id,namespace,do_public,validity,signature,version)


def verify_do_certificate(cert,kgc_public,sys_id,namespace,clock):
    if clock is None: raise ProtocolRejectedError('clock unavailable')
    fields=cert_fields(cert)
    if cert.sys_id!=sys_id or cert.namespace!=namespace:
        raise ProtocolRejectedError('DO certificate scope mismatch')
    verify_canonical(kgc_public,cert.kgc_signature,'MYABE-DO-CERT',*fields)
    now=clock.now()
    if type(now) is not int or not cert.validity.not_before<=now<cert.validity.not_after:
        raise ProtocolRejectedError('DO certificate validity rejected')
    return cert.publisher_public_key


def _context_record(ctx):
    if type(ctx) is not PolicyContext: raise ContractError('PolicyContext required')
    return StructuredRecord('MYABE08.PolicyContextV1',(
        ('sys_id',ctx.sys_id),('policy_context_id',ctx.policy_context_id),
        ('policy_version',UInt64(ctx.policy_version)),('ctx_priv',ctx.ctx_priv)))


def _kem_record(info,backend):
    if type(info) is not KEMDEMInfo: raise ContractError('KEMDEMInfo required')
    profile=info.profile
    if (profile.pairing_profile_id!=SECURITY_PROFILE_BLS12_381 or
        profile.tee_profile_id not in (EMULATED_TEE_PROFILE,SGX_DEBUG_GRAMINE_V1) or
        profile.encoding_version not in (MYABE08_ENCODING_V1,
                                        MYABE08_ROW_ABLATION_ENCODING_V1) or
        (profile.encoding_version==MYABE08_ROW_ABLATION_ENCODING_V1 and
         profile.tee_profile_id!=EMULATED_TEE_PROFILE) or
        backend.binding.security_profile_id!=profile.pairing_profile_id):
        raise ContractError('unsupported publication profile')
    return StructuredRecord('MYABE08.KEMDEMInfoV1',(
        ('security_profile_id',profile.pairing_profile_id),
        ('tee_profile_id',profile.tee_profile_id),
        ('encoding_profile_id',profile.encoding_version),
        ('curve_id',backend.binding.curve_id),('backend_id',backend.binding.backend_id),
        ('dem_id',info.dem_id),('kdf_id',info.kdf_id),
        ('nonce_bytes',UInt32(info.nonce_bytes))))


def header_record_ct(header,backend):
    if type(header) is not CiphertextHeader: raise ContractError('CiphertextHeader required')
    if header.af_header.sys_id!=backend.binding.sys_id or header.context.sys_id!=backend.binding.sys_id:
        raise ContractError('header SysID mismatch')
    for name in ('core_components_digest','af_metadata_digest','filter_digest'):
        require_bytes(getattr(header,name),name,32)
    require_bytes(header.data_id,'DataID')
    if not header.data_id or header.c_max!=header.af_header.parameters.c_max:
        raise ContractError('invalid header shape')
    return StructuredRecord('MYABE08.CiphertextHeaderV1',(
        ('af_header',header_record(header.af_header)),
        ('ctx_priv',header.context.ctx_priv),
        ('policy_context_id',header.context.policy_context_id),
        ('policy_version',UInt64(header.context.policy_version)),
        ('data_id',header.data_id),
        ('c',backend.serialize_g1(header.c,allow_identity=False)),
        ('c_max',UInt32(header.c_max)),
        ('core_components_digest',header.core_components_digest),
        ('af_metadata_digest',header.af_metadata_digest),
        ('filter_digest',header.filter_digest),
        ('kem_dem_info',_kem_record(header.kem_dem_info,backend))))


def header_digest(header,backend):
    return hashlib.sha256(encode(header_record_ct(header,backend))).digest()


def compute_ctx_ct(header,backend):
    return hashlib.sha256(encode(('CT',header_record_ct(header,backend)))).digest()


def dem_content_digest(nonce,ciphertext):
    require_bytes(nonce,'DEM nonce',12)
    require_bytes(ciphertext,'DEM ciphertext')
    return hashlib.sha256(encode((nonce,ciphertext))).digest()


def build_publication(core,index,af_header,context,data_id,message,do_private,cert,backend,
                      *,tee_profile_id=EMULATED_TEE_PROFILE,
                      component_allocation='OCCURRENCE',stage_timings_ns=None):
    """Assemble a signed public CT after AF success, with no digest cycle."""
    from .algebra import EncryptCoreResult
    from .crypto import compute_ctx_priv
    if type(core) is not EncryptCoreResult or core.binding!=backend.binding:
        raise ContractError('EncryptCoreResult binding mismatch')
    if type(context) is not PolicyContext or context.ctx_priv!=compute_ctx_priv(
            context.sys_id,context.policy_context_id,context.policy_version):
        raise ContractError('context digest mismatch')
    if (af_header.sys_id!=context.sys_id or af_header.ctx_priv!=context.ctx_priv or
        af_header.ell!=core.matrix.ell or af_header.parameters.c_max!=core.c_max or
        af_header.matrix_digest!=matrix_digest(core.matrix,backend) or
        index.metadata.u!=af_header.distinct_tokens or
        index.metadata.sys_id!=context.sys_id):
        raise ContractError('AF/header/core mismatch')
    filter_digest(index)
    if public_key_bytes(do_private)!=cert.publisher_public_key or cert.sys_id!=context.sys_id:
        raise ContractError('DO signing key/certificate mismatch')
    if tee_profile_id not in (EMULATED_TEE_PROFILE,SGX_DEBUG_GRAMINE_V1):
        raise ContractError('unsupported publication TEE profile')
    if component_allocation not in ('OCCURRENCE','ROW'):
        raise ContractError('unknown component allocation')
    if component_allocation=='ROW' and tee_profile_id!=EMULATED_TEE_PROFILE:
        raise ContractError('row ablation is EMULATED TEST only')
    if len(core.d_j)!=(core.c_max if component_allocation=='OCCURRENCE'
                       else core.matrix.ell):
        raise ContractError('component allocation/shape mismatch')
    encoding=(MYABE08_ENCODING_V1 if component_allocation=='OCCURRENCE'
              else MYABE08_ROW_ABLATION_ENCODING_V1)
    info=KEMDEMInfo(ProfileMetadata(SECURITY_PROFILE_BLS12_381,
                                    tee_profile_id,encoding))
    header=CiphertextHeader(af_header,context,data_id,core.c,core.c_max,
        core_components_digest(core.c_i,core.d_j,backend),
        af_metadata_digest(index),filter_digest(index),info)
    dem_started=perf_counter_ns() if stage_timings_ns is not None else None
    ctx_ct=compute_ctx_ct(header,backend)
    sealed=dem_encrypt(ctx_ct,backend.serialize_gt(core.e),message)
    if stage_timings_ns is not None:
        stage_timings_ns['dem_encrypt_ns']=perf_counter_ns()-dem_started
        sign_started=perf_counter_ns()
    signature=sign_canonical(do_private,'MYABE-PUBLISH',header_digest(header,backend),
                             dem_content_digest(sealed.nonce,sealed.ciphertext))
    if stage_timings_ns is not None:
        stage_timings_ns['publication_sign_ns']=perf_counter_ns()-sign_started
    ct=Ciphertext(core.c_i,core.d_j,core.matrix.rows,index,sealed.nonce,
                  sealed.ciphertext,header,signature,cert)
    return ct


def verify_publication(ct,backend,kgc_public,expected_namespace,clock):
    """Verify complete public components. This is not an ABE well-formedness proof."""
    from .crypto import compute_ctx_priv
    from .lsss import LSSSMatrix
    if type(ct) is not Ciphertext: raise ContractError('Ciphertext required')
    h=ct.header
    verify_do_certificate(ct.publisher_certificate,kgc_public,
                          backend.binding.sys_id,expected_namespace,clock)
    if (h.context.ctx_priv!=compute_ctx_priv(h.context.sys_id,
            h.context.policy_context_id,h.context.policy_version) or
        h.context.ctx_priv!=h.af_header.ctx_priv):
        raise ProtocolRejectedError('context mismatch')
    matrix=LSSSMatrix(ct.matrix,backend.scalar_order,len(ct.matrix),len(ct.matrix[0]))
    if (h.af_header.matrix_digest!=matrix_digest(matrix,backend) or
        h.af_header.ell!=matrix.ell or h.af_header.distinct_tokens!=ct.anonymous_filter.metadata.u or
        h.af_header.sys_id!=backend.binding.sys_id or
        ct.anonymous_filter.metadata.ell!=h.af_header.ell or
        ct.anonymous_filter.metadata.c_max!=h.c_max or
        len(ct.occurrence_components)!=(h.c_max if
            h.kem_dem_info.profile.encoding_version==MYABE08_ENCODING_V1
            else matrix.ell) or len(ct.row_components)!=matrix.ell or
        h.core_components_digest!=core_components_digest(ct.row_components,ct.occurrence_components,backend) or
        h.af_metadata_digest!=af_metadata_digest(ct.anonymous_filter) or
        h.filter_digest!=filter_digest(ct.anonymous_filter)):
        raise ProtocolRejectedError('ciphertext digest/shape mismatch')
    header_digest(h,backend)
    verify_canonical(ct.publisher_certificate.publisher_public_key,
        ct.publication_signature,'MYABE-PUBLISH',header_digest(h,backend),
        dem_content_digest(ct.dem_nonce,ct.encrypted_message))
    return compute_ctx_ct(h,backend)


def public_algebra_from_ciphertext(ct,backend):
    """CSP view contains no E or policy token list."""
    from .algebra import PublicAlgebraCiphertext
    from .lsss import LSSSMatrix
    matrix=LSSSMatrix(ct.matrix,backend.scalar_order,len(ct.matrix),len(ct.matrix[0]))
    return PublicAlgebraCiphertext(backend.binding,matrix,ct.row_components,
                                   ct.occurrence_components,ct.header.c,ct.header.c_max)
