"""Anonymous Authorization Enclave port -- SOFTWARE EMULATION ONLY.

No SGX isolation, hardware attestation, side-channel resistance, hardware
sealing, trusted-clock implementation, or enclave timing claim. The
software authorization path requires a current-state coordinator;
the public eight-algorithm entry point remains unimplemented.
"""

from typing import Optional, Tuple

from .credential import AttestedConfidentialChannel
from .errors import unimplemented
from .metrics import TEEMetrics
from .profile import EMULATED_TEE_PROFILE, tee_profile
from .state import CurrentStateCoordinator, TrustedClock
from .types import (
    Attribute, AuthorizationResult, Credential, NamespaceCertificate,
    PolicyContext, PossessionProof, PublicParameters,
    RevocationStateResult, RevocationUpdate, SealedUserBlob, TEERequest,
    TEEState, UserBaseState, UserProvisioningResult,
)


class EmulatedAnonymousAuthorizationEnclave:
    """Independent service, never a subclass of MyABE08.

    Credential/blob/plain UID are private channel inputs; result.tee_state is
    internal orchestration only. Only result.authorization may reach CSP.
    """

    def __init__(self, *, profile: str = EMULATED_TEE_PROFILE,
                 coordinator: Optional[CurrentStateCoordinator] = None,
                 clock: Optional[TrustedClock] = None,
                 revocation_engine=None):
        self.profile = tee_profile(profile)
        from .state import UnavailableCurrentStateCoordinator, TEEIssueStore
        self.coordinator = UnavailableCurrentStateCoordinator() if coordinator is None else coordinator
        self.clock = clock
        self.revocation_engine = revocation_engine
        self._issue_store = TEEIssueStore()

    def provision_user(self, pp: PublicParameters, state: TEEState,
                       base_state: UserBaseState, *,
                       channel: AttestedConfidentialChannel) -> UserProvisioningResult:
        """KGC->TEE confidential base state; never accepts RK or MSK."""
        unimplemented("TEE user provisioning/sealing")

    def tokenize_policy(self, pp: PublicParameters, state: TEEState,
                        labels: Tuple[Attribute, ...], context: PolicyContext, *,
                        namespace_certificate: NamespaceCertificate,
                        channel: AttestedConfidentialChannel) -> Tuple[bytes, ...]:
        """DO-only namespace/batch-authorized tokenization; never a DU oracle."""
        unimplemented("TEE policy contextual tokenization")

    def rev_state_upt(self, pp: PublicParameters, state: TEEState,
                      update: RevocationUpdate, *,
                      channel: AttestedConfidentialChannel) -> RevocationStateResult:
        """Exact set, next version/previous digest, atomic persistence and Ack."""
        unimplemented("TEE RevStateUpt")

    def authorize(self, pp: PublicParameters, state: TEEState,
                  credential: Credential, blob: SealedUserBlob, request: TEERequest, *,
                  channel: AttestedConfidentialChannel, possession: PossessionProof,
                  metrics: Optional[TEEMetrics] = None) -> AuthorizationResult:
        """Eight checks/stages from section 5.6; no caller-chosen attributes.

        Verify credential/current version/possession/blob/publication/context;
        acquire fresh serialized current-head permit; exact RevSet lookup;
        tokenize full certified attributes; sample delta and reject mu_q=0 or
        K0_q=identity; produce T0 with one pairing; sign bound capability; commit
        nonce once before release. Missing any dependency must fail closed.
        """
        unimplemented("TEEAuthorize (software emulation not implemented)")

    def authorize_with_state_coordinator(self, publication, host_request,
            encrypted_private_record, server_channel, *, backend, algebra_pp,
            kgc_public_key, cap_private_key, k_tok, registry, sealing_service,
            expected_namespace, issue_store=None, metrics=None):
        """Fail-closed software authorization; a live coordinator is mandatory."""
        try:
            return self._authorize_with_state_coordinator_impl(
                publication,host_request,encrypted_private_record,server_channel,
                backend=backend,algebra_pp=algebra_pp,kgc_public_key=kgc_public_key,
                cap_private_key=cap_private_key,k_tok=k_tok,registry=registry,
                sealing_service=sealing_service,expected_namespace=expected_namespace,
                issue_store=issue_store,metrics=metrics)
        except Exception:
            if metrics is not None: metrics.request_issue_rejections+=1
            raise

    def _authorize_with_state_coordinator_impl(self, publication, host_request,
            encrypted_private_record, server_channel, *, backend, algebra_pp,
            kgc_public_key, cap_private_key, k_tok, registry, sealing_service,
            expected_namespace, issue_store=None, metrics=None):
        """EMULATED protocol path with REQUIRED online coordinator permit.

        This is not complete TEEAuthorize: real RevSet/current-head service,
        rollback protection, hardware isolation and trusted time are absent.
        Credential/blob/UID arrive only inside an encrypted channel record.
        """
        from .algebra import AlgebraOperationCounts, UserAlgebraBaseState, derive_ephemeral_algebra
        from .capability import bundle_digest,from_ephemeral,sign_capability,authorization_bytes
        from .channel import EmulatedChannelEndpoint
        from .credential import (CredentialVersionRegistry,certified_user_tokens,decode_private_ingress,
                                 verify_credential,verify_possession)
        from .encoding import require_bytes
        from .errors import ContractError,ProtocolRejectedError,StateSynchronizationError
        from .publication import header_digest,verify_publication
        from .state import TEEIssueStore
        from .revocation import LinearizedCurrentHeadCoordinator
        from .types import Ciphertext
        from .metrics import AUTH_STAGE_TIMING_FIELDS
        from time import perf_counter_ns
        stages=metrics.stage_timings_ns if metrics is not None else None
        if stages is not None:
            stages.update((name,0) for name in AUTH_STAGE_TIMING_FIELDS)
        if self.clock is None:
            raise ProtocolRejectedError('software clock unavailable')
        if (type(server_channel) is not EmulatedChannelEndpoint or
            type(publication) is not Ciphertext or
            type(host_request) is not EmulatedHostRequest):
            raise ContractError('emulated authorization input shape mismatch')
        request=host_request
        now=self.clock.now()
        if type(now) is not int or request.expiry<=now:
            raise ProtocolRejectedError('request expired')
        if (type(request.version_hint) is not int or request.version_hint<0 or
                request.version_hint>0xFFFFFFFFFFFFFFFF):
            raise ContractError('invalid untrusted version hint')
        require_bytes(request.request_nonce,'request nonce')
        if len(request.request_nonce)<32: raise ContractError('request nonce requires 32 bytes')
        binding=server_channel.binding
        if (request.session_id!=binding.session_id or
            request.challenge!=binding.fresh_challenge or
            request.header_digest!=header_digest(publication.header,backend) or
            request.ctx_priv!=publication.header.context.ctx_priv):
            raise ProtocolRejectedError('request/channel/header mismatch')
        # Channel decrypt precedes all handling of private credential/blob data.
        private_bytes=server_channel.receive(encrypted_private_record)
        if metrics is not None: metrics.channel_records+=1
        credential,blob,proof=decode_private_ingress(private_bytes)
        credential_started=perf_counter_ns() if stages is not None else None
        verify_credential(kgc_public_key,credential,backend.binding.sys_id,
                          registry,self.clock)
        if metrics is not None: metrics.credential_verifications+=1
        if (self.revocation_engine is not None and self.revocation_engine.metrics is not None
                and type(registry) is CredentialVersionRegistry):
            self.revocation_engine.metrics.credential_registry_entries=registry.count()
        verify_possession(credential,proof,binding,request.header_digest,request.request_nonce)
        if stages is not None:
            stages['credential_verify_ns']=perf_counter_ns()-credential_started
        if metrics is not None: metrics.possession_verifications+=1
        base=sealing_service.unseal(blob,credential)
        if metrics is not None:
            metrics.blob_unseals+=1
            metrics.sealed_blob_bytes+=len(blob.opaque)
        if base.sys_id!=backend.binding.sys_id:
            raise ProtocolRejectedError('sealed SysID mismatch')
        verify_publication(publication,backend,kgc_public_key,expected_namespace,self.clock)
        if metrics is not None: metrics.publication_verifications+=1
        if algebra_pp.binding!=backend.binding or algebra_pp.g2_a.binding!=backend.binding:
            raise ContractError('algebra PP binding mismatch')
        if issue_store is None:
            issue_store=self._issue_store
        if type(issue_store) is not TEEIssueStore:
            raise ContractError('TEEIssueStore required')
        issue_store.reserve(backend.binding.sys_id,request.request_nonce)
        try:
            coordination_started=perf_counter_ns() if stages is not None else None
            with self.coordinator.authorization_transaction(
                sys_id=backend.binding.sys_id,fresh_nonce=request.request_nonce) as txn:
                permit=txn.current_head()
                if (not permit.active or permit.sys_id!=backend.binding.sys_id or
                    permit.fresh_nonce!=request.request_nonce or
                    type(permit.rev_version) is not int or permit.rev_version<0 or
                    not permit.transaction_id or not permit.authenticated_record):
                    raise StateSynchronizationError('current-state permit rejected')
                if stages is not None:
                    stages['state_coordination_ns']=perf_counter_ns()-coordination_started
                if isinstance(self.coordinator,LinearizedCurrentHeadCoordinator):
                    if self.revocation_engine is None:
                        raise StateSynchronizationError('TEE revocation state unavailable')
                    revset_started=perf_counter_ns() if stages is not None else None
                    self.coordinator.verify_permit(permit)
                    try:
                        self.revocation_engine.check_active(credential.uid,permit)
                    except ProtocolRejectedError:
                        if metrics is not None: metrics.revoked_rejections+=1
                        raise
                    finally:
                        if stages is not None:
                            stages['revset_lookup_ns']=perf_counter_ns()-revset_started
                    if metrics is not None:
                        metrics.rev_lookup_count+=1
                        metrics.state_digest_checks+=1
                tokenization_started=perf_counter_ns() if stages is not None else None
                tokens=certified_user_tokens(credential,k_tok,
                    publication.header.context.policy_context_id,
                    publication.header.context.policy_version)
                if stages is not None:
                    stages['tokenization_ns']=perf_counter_ns()-tokenization_started
                if metrics is not None: metrics.user_token_prf_count+=len(credential.attributes)
                algebra_base=UserAlgebraBaseState(backend.binding,base.mu,base.k0)
                pair_counts=AlgebraOperationCounts()
                ephemeral=derive_ephemeral_algebra(algebra_pp,algebra_base,tokens,
                    publication.header.c,backend,counts=pair_counts,
                    stage_timings_ns=stages)
                if pair_counts.pairing_terms!=1:
                    raise ContractError('T0 pairing count mismatch')
                if metrics is not None:
                    metrics.h0_count+=len(tokens)
                    metrics.t0_pairings+=pair_counts.pairing_terms
                bundle=from_ephemeral(ephemeral)
                cap_started=perf_counter_ns() if stages is not None else None
                auth=sign_capability(cap_private_key,backend.binding.sys_id,
                    request.header_digest,request.ctx_priv,permit.rev_version,
                    request.request_nonce,request.expiry,bundle,backend)
                if stages is not None:
                    stages['cap_sign_ns']=perf_counter_ns()-cap_started
                if metrics is not None:
                    metrics.cap_signatures+=1
                    metrics.auth_canonical_bytes+=len(authorization_bytes(auth,backend))
                txn.commit_authorization(request.request_nonce,bundle_digest(bundle,backend))
                issue_store.mark_issued(backend.binding.sys_id,request.request_nonce)
                return auth
        except Exception:
            issue_store.abort(backend.binding.sys_id,request.request_nonce)
            raise

    def tokenize_policy_emulated(self, encrypted_labels_record, server_channel, *,
            certificate, do_proof, context, expected_namespace, kgc_public_key,
            k_tok, backend, metrics=None):
        """DO-only software channel path; labels are never host RPC fields."""
        from .channel import EmulatedChannelEndpoint
        from .credential import canonical_attributes
        from .crypto import compute_ctx_priv,contextual_token
        from .encoding import decode,encode_attribute
        from .errors import ContractError,ProtocolRejectedError
        from .publication import verify_do_certificate
        from .signing import verify_canonical
        if self.clock is None: raise ProtocolRejectedError('software clock unavailable')
        if type(server_channel) is not EmulatedChannelEndpoint:
            raise ContractError('emulated channel required')
        verify_do_certificate(certificate,kgc_public_key,backend.binding.sys_id,
                              expected_namespace,self.clock)
        raw=server_channel.receive(encrypted_labels_record)
        labels=decode_policy_labels(raw)
        if any(a.namespace!=expected_namespace for a in labels):
            raise ProtocolRejectedError('policy namespace mismatch')
        if (context.sys_id!=backend.binding.sys_id or
            context.ctx_priv!=compute_ctx_priv(context.sys_id,
                context.policy_context_id,context.policy_version)):
            raise ProtocolRejectedError('policy context mismatch')
        verify_canonical(certificate.publisher_public_key,do_proof,
            'MYABE-DO-TOKENIZE',*policy_proof_fields(context,raw,server_channel.binding))
        result=tuple(contextual_token(k_tok,context.sys_id,context.ctx_priv,
                    encode_attribute(a.namespace,a.name,a.value)) for a in labels)
        if metrics is not None:
            metrics.policy_token_prf_count+=len(set(result))
            metrics.channel_records+=1
        return result


from dataclasses import dataclass
import hashlib
import secrets
from .encoding import decode,encode,require_bytes,UInt64
from .errors import ContractError


@dataclass(frozen=True)
class EmulatedHostRequest:
    """CSP-visible request fields only; no UID, credential or blob digest."""
    header_digest: bytes
    ctx_priv: bytes
    request_nonce: bytes
    expiry: int
    session_id: bytes
    challenge: bytes
    version_hint: int = 0  # untrusted; never substitutes for fresh current head


def make_emulated_host_request(publication,backend,channel,expiry,*,nonce=None,
                               version_hint=0):
    from .publication import header_digest
    if nonce is None: nonce=secrets.token_bytes(32)
    require_bytes(nonce,'request nonce')
    if len(nonce)<32: raise ContractError('request nonce requires 32 bytes')
    if (type(version_hint) is not int or version_hint<0 or
            version_hint>0xFFFFFFFFFFFFFFFF):
        raise ContractError('invalid untrusted version hint')
    return EmulatedHostRequest(header_digest(publication.header,backend),
        publication.header.context.ctx_priv,nonce,expiry,
        channel.binding.session_id,channel.binding.fresh_challenge,version_hint)


def encode_policy_labels(labels):
    from .credential import canonical_attributes
    from .encoding import encode_attribute
    if type(labels) is not tuple or not labels:
        raise ContractError('policy labels tuple required')
    for a in labels: canonical_attributes((a,))
    return encode(('MYABE-DO-POLICY-LABELS',tuple(
        encode_attribute(a.namespace,a.name,a.value) for a in labels)))


def decode_policy_labels(raw):
    from .credential import canonical_attributes
    from .encoding import StructuredRecord
    from .types import Attribute
    obj=decode(raw)
    if type(obj) is not tuple or len(obj)!=2 or obj[0]!='MYABE-DO-POLICY-LABELS' or type(obj[1]) is not tuple:
        raise ContractError('policy label envelope malformed')
    labels=[]
    for item in obj[1]:
        record=decode(item)
        if type(record) is not StructuredRecord or record.schema!='MYABE08.AttributeV1' or tuple(k for k,_ in record.fields)!=('namespace','name','value'):
            raise ContractError('policy attribute malformed')
        labels.append(Attribute(*(v for _,v in record.fields)))
    if encode_policy_labels(tuple(labels))!=raw: raise ContractError('noncanonical policy label envelope')
    return tuple(labels)


def policy_proof_fields(context,raw,binding):
    return (context.sys_id,context.ctx_priv,binding.session_id,binding.fresh_challenge,
            binding.transcript_digest,hashlib.sha256(raw).digest())


def sign_do_policy_proof(do_private,context,raw,binding):
    from .signing import sign_canonical
    return sign_canonical(do_private,'MYABE-DO-TOKENIZE',
                          *policy_proof_fields(context,raw,binding))
