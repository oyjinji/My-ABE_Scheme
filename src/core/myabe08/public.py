"""Public eight-algorithm TEST facade for the real SGX DEBUG feasibility path.

This facade composes the audited MYABE-08 primitives. It does not implement
ABE algebra, attest a current TCB, or provide production key persistence.
"""

from dataclasses import dataclass, field
from pathlib import Path
import secrets
import time

from .af import ProtectedPayloadAF, compute_ctx_af
from .algebra import (AlgebraOperationCounts, encrypt_algebra_core,
                      finaldec_algebra_core, keygen_algebra_core,
                      setup_algebra_core)
from .capability import csp_transform_verified, verify_capability
from .credential import (CredentialVersionRegistry, credential_digest,
                         encode_private_ingress, issue_credential, sign_possession)
from .attestation import EmulatedChallengeStore, issue_emulated_evidence
from .channel import (establish_emulated_channel, x25519_private_new,
                      x25519_public_bytes)
from .crypto import BLS12381Backend, DEMCiphertext, compute_ctx_priv, dem_decrypt
from .encoding import UInt32, UInt64, decode, encode
from .errors import ContractError, ProtocolRejectedError, UnsupportedProfileError
from .lsss import LSSSMatrix, prepare_policy_rows
from .profile import (EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1,
                      MYABE08_ENCODING_V1, MYABE08_ROW_ABLATION_ENCODING_V1)
from .publication import (build_publication, compute_ctx_ct, header_digest,
                          issue_do_certificate, make_af_header, verify_publication)
from .real_tee.attested_session import FEASIBILITY_MODE, STRICT_MODE
from .real_tee.client import SgxDebugClient, SgxHeadRpcProxy
from .real_tee.identity_policy import SgxIdentityPolicy
from .revocation import (EmulatedPersistentKGCStateStore, KGCRevocationManager,
                         EmulatedPersistentRevocationStore,
                         EmulatedPersistentCurrentHeadStore,
                         LinearizedCurrentHeadCoordinator, TEERevocationEngine,
                         sign_management_command)
from .sealing import EmulatedSealingService, SCHEMA_VERSION
from .signing import new_private_key, public_key_bytes
from .state import CSPRequestState, DURequestState, TEEIssueStore
from .tee import (EmulatedAnonymousAuthorizationEnclave, EmulatedHostRequest,
                  encode_policy_labels, make_emulated_host_request,
                  sign_do_policy_proof)
from .types import (PolicyContext, PolicyInput, SealedUserBlob, UserBaseState,
                    Validity)


CURRENT_HEAD_MODE = 'TEST_SINGLE_LOGICAL_COORDINATOR'
EMULATED_TEST_MODE = 'EMULATED_TEST'


@dataclass(frozen=True)
class PublicSetup:
    pp: object
    msk: object = field(repr=False)
    metadata: dict = field(repr=False)


@dataclass(frozen=True)
class PublicUser:
    credential: object = field(repr=False)
    recovery_key: object = field(repr=False)
    blob: SealedUserBlob = field(repr=False)


@dataclass(frozen=True)
class PublicAuth:
    authorization: object
    request: object = field(repr=False)
    du_state: DURequestState = field(repr=False)
    tee_pairings: int = 0


@dataclass(frozen=True)
class PublicPartial:
    ciphertext: object
    public_auth: PublicAuth
    t_a: object
    candidate_rows: tuple
    reconstruction_rows: tuple
    occurrence_slots: tuple
    csp_pairings: int


def _public_profile(ciphertext, backend):
    profile = ciphertext.header.kem_dem_info.profile.tee_profile_id
    if (profile not in (SGX_DEBUG_GRAMINE_V1, EMULATED_TEE_PROFILE) or
            ciphertext.header.context.sys_id != backend.binding.sys_id):
        raise ContractError('public profile/SysID mismatch')
    return profile


def serialize_ciphertext(ciphertext, backend: BLS12381Backend) -> bytes:
    """Shared canonical CT wrapper for both supported TEST backends."""
    from .real_tee.messages import encode_publication
    profile = _public_profile(ciphertext, backend)
    return encode(('MYABE08-PUBLIC-CT-V1', profile, backend.binding.sys_id,
                   encode_publication(ciphertext, backend)))


def parse_ciphertext(raw: bytes, backend: BLS12381Backend, *,
                     expected_profile: str = SGX_DEBUG_GRAMINE_V1):
    from .real_tee.messages import decode_publication
    value = decode(raw)
    if (type(value) is not tuple or len(value) != 4 or
            value[0] != 'MYABE08-PUBLIC-CT-V1' or
            value[1] != expected_profile or value[2] != backend.binding.sys_id):
        raise ContractError('CT wrapper version/profile/SysID mismatch')
    ciphertext = decode_publication(value[3], backend,
                                    expected_profile=expected_profile)
    if serialize_ciphertext(ciphertext, backend) != raw:
        raise ContractError('noncanonical CT wrapper')
    return ciphertext


def _request_wire(request):
    return (request.header_digest, request.ctx_priv, request.request_nonce,
            UInt64(request.expiry), request.session_id, request.challenge,
            UInt64(request.version_hint))


def _parse_request(value):
    if (type(value) is not tuple or len(value) != 7 or
            type(value[3]) is not UInt64 or type(value[6]) is not UInt64):
        raise ContractError('Auth request wire malformed')
    return EmulatedHostRequest(value[0], value[1], value[2], value[3].value,
                               value[4], value[5], value[6].value)


def serialize_authorization(public_auth: PublicAuth, ciphertext,
                            backend: BLS12381Backend) -> bytes:
    """Auth transport is bound to its CT; profile is not a caller-only claim."""
    from .capability import authorization_bytes, bundle_digest
    if type(public_auth) is not PublicAuth or public_auth.tee_pairings != 1:
        raise ContractError('PublicAuth with one TEE pairing required')
    profile = _public_profile(ciphertext, backend)
    cap = public_auth.authorization.capability
    request = public_auth.request
    digest = header_digest(ciphertext.header, backend)
    if (cap.sys_id != backend.binding.sys_id or cap.header_digest != digest or
            cap.ctx_priv != ciphertext.header.context.ctx_priv or
            cap.bundle_digest != bundle_digest(public_auth.authorization.bundle, backend) or
            request.header_digest != digest or request.ctx_priv != cap.ctx_priv or
            request.request_nonce != cap.request_nonce or request.expiry != cap.expiry):
        raise ContractError('Auth/CT/request binding mismatch')
    public_auth.du_state.verify_response_binding(request, public_auth.authorization)
    return encode(('MYABE08-PUBLIC-AUTH-V1', profile, backend.binding.sys_id,
        digest, authorization_bytes(public_auth.authorization, backend),
        _request_wire(request), UInt32(public_auth.tee_pairings)))


def parse_authorization(raw: bytes, ciphertext, backend: BLS12381Backend, *,
                        expected_profile: str = SGX_DEBUG_GRAMINE_V1) -> PublicAuth:
    from .real_tee.messages import decode_authorization
    value = decode(raw)
    if (type(value) is not tuple or len(value) != 7 or
            value[0] != 'MYABE08-PUBLIC-AUTH-V1' or
            value[1] != expected_profile or value[2] != backend.binding.sys_id or
            _public_profile(ciphertext, backend) != expected_profile or
            value[3] != header_digest(ciphertext.header, backend) or
            type(value[6]) is not UInt32):
        raise ContractError('Auth wrapper version/profile/SysID mismatch')
    request = _parse_request(value[5])
    auth = PublicAuth(decode_authorization(value[4], backend), request,
                      DURequestState.from_host_request(request), value[6].value)
    if serialize_authorization(auth, ciphertext, backend) != raw:
        raise ContractError('noncanonical Auth wrapper')
    return auth


def _rows(item):
    if type(item) is not tuple or any(type(x) is not UInt32 for x in item):
        raise ContractError('partial row encoding malformed')
    return tuple(x.value for x in item)


def serialize_partial(partial: PublicPartial, backend: BLS12381Backend) -> bytes:
    """Canonical CT' envelope; no RK or private ingress is serialized."""
    if type(partial) is not PublicPartial:
        raise ContractError('PublicPartial required')
    profile = _public_profile(partial.ciphertext, backend)
    if partial.csp_pairings != 1 + len(partial.occurrence_slots):
        raise ContractError('partial pairing count mismatch')
    return encode(('MYABE08-PUBLIC-PARTIAL-V1', profile,
        serialize_ciphertext(partial.ciphertext, backend),
        serialize_authorization(partial.public_auth, partial.ciphertext, backend),
        backend.serialize_gt(partial.t_a),
        tuple(UInt32(x) for x in partial.candidate_rows),
        tuple(UInt32(x) for x in partial.reconstruction_rows),
        tuple(UInt32(x) for x in partial.occurrence_slots),
        UInt32(partial.csp_pairings)))


def parse_partial(raw: bytes, backend: BLS12381Backend, *,
                  expected_profile: str = SGX_DEBUG_GRAMINE_V1) -> PublicPartial:
    value = decode(raw)
    if (type(value) is not tuple or len(value) != 9 or
            value[0] != 'MYABE08-PUBLIC-PARTIAL-V1' or
            value[1] != expected_profile or type(value[8]) is not UInt32):
        raise ContractError('partial wire version/profile/shape mismatch')
    ciphertext = parse_ciphertext(value[2], backend, expected_profile=expected_profile)
    public_auth = parse_authorization(value[3], ciphertext, backend,
                                      expected_profile=expected_profile)
    partial = PublicPartial(ciphertext, public_auth,
        backend.deserialize_gt(value[4], binding=backend.binding),
        _rows(value[5]), _rows(value[6]), _rows(value[7]), value[8].value)
    if serialize_partial(partial, backend) != raw:
        raise ContractError('noncanonical partial wire')
    return partial


class PublicMyABE08:
    """Explicit TEST backend; ROW is an EMULATED internal ablation only."""

    def __init__(self, *, sys_id: bytes, namespace: str, backend: str,
                 experiment_trust_mode: str, identity_policy: SgxIdentityPolicy = None,
                 state_path: Path, clock, client: SgxDebugClient = None,
                 test_tee_bootstrap: bool = False,
                 component_allocation: str = 'OCCURRENCE'):
        if type(sys_id) is not bytes or not sys_id or type(namespace) is not str or not namespace:
            raise ContractError('SysID and namespace required')
        if backend not in (EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1):
            raise UnsupportedProfileError('unknown TEE backend')
        if backend == SGX_DEBUG_GRAMINE_V1:
            if experiment_trust_mode not in (FEASIBILITY_MODE, STRICT_MODE):
                raise UnsupportedProfileError('explicit attestation policy required')
            if type(identity_policy) is not SgxIdentityPolicy or not test_tee_bootstrap:
                raise ContractError('TEST identity policy and explicit TEST bootstrap required')
        elif experiment_trust_mode != EMULATED_TEST_MODE:
            raise UnsupportedProfileError('explicit EMULATED_TEST mode required')
        if component_allocation not in ('OCCURRENCE', 'ROW'):
            raise UnsupportedProfileError('unknown component allocation')
        if component_allocation == 'ROW' and backend != EMULATED_TEE_PROFILE:
            raise UnsupportedProfileError('row ablation is EMULATED TEST only')
        if clock is None or not callable(getattr(clock, 'now', None)):
            raise ContractError('clock required')
        self.sys_id, self.namespace = sys_id, namespace
        self.backend_id, self.experiment_trust_mode = backend, experiment_trust_mode
        self.component_allocation = component_allocation
        self.identity_policy, self.state_path, self.clock = identity_policy, Path(state_path), clock
        self.client = client if client is not None else SgxDebugClient()
        self.crypto = BLS12381Backend(sys_id)
        self.spans_ns = {}
        self.authorize_breakdown_ns = []
        self.encrypt_breakdown_ns = []
        self.transform_breakdown_ns = []
        self.finaldec_breakdown_ns = []
        self.current_head_mode = CURRENT_HEAD_MODE
        self._ready = False
        self._csp_state = CSPRequestState()

    def _start(self):
        return time.perf_counter_ns()

    def _end(self, name, started):
        self.spans_ns.setdefault(name, []).append(time.perf_counter_ns() - started)

    def _emulated_channel(self, purpose='DU'):
        """TEST software evidence and fresh X25519 channel, never SGX evidence."""
        measurement = b'MYABE08-EMULATED-TEST-MEASUREMENT'[:32]
        challenge, session_id = secrets.token_bytes(32), secrets.token_bytes(32)
        server_private, client_private = x25519_private_new(), x25519_private_new()
        evidence = issue_emulated_evidence(self._root_key, self.sys_id,
            measurement, 3, challenge, x25519_public_bytes(server_private),
            session_id)
        return establish_emulated_channel(client_private, server_private,
            evidence, public_key_bytes(self._root_key), self.sys_id,
            measurement, 2, challenge, self._challenges, purpose=purpose)

    def _require_ready(self):
        if not self._ready:
            raise ProtocolRejectedError('STATE_UNAVAILABLE')
        if self.backend_id == EMULATED_TEE_PROFILE:
            return
        # Restart or loss of the exact SGX instance invalidates the TEST state.
        try:
            health = self.client.health()
        except (OSError, TimeoutError, ConnectionError) as exc:
            raise ProtocolRejectedError('STATE_UNAVAILABLE') from exc
        if health[3] != self._instance or health[2].value != 1:
            raise ProtocolRejectedError('STATE_UNAVAILABLE')

    def _require_allocation(self, ciphertext):
        expected=(MYABE08_ROW_ABLATION_ENCODING_V1 if
                  self.component_allocation == 'ROW' else MYABE08_ENCODING_V1)
        if ciphertext.header.kem_dem_info.profile.encoding_version != expected:
            raise UnsupportedProfileError('ciphertext/ablation profile mismatch')

    def Setup(self, *, c_max: int, validity: Validity):
        started = self._start()
        if self._ready:
            raise ProtocolRejectedError('Setup already executed')
        if type(validity) is not Validity:
            raise ContractError('Validity required')
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            # QVL and explicit TCB policy gate precede TEST secret bootstrap.
            preflight_started = time.perf_counter_ns()
            checked = self.client.open_quote_bound_test_session(self.sys_id,
                self.identity_policy,
                allow_outdated_debug_feasibility=self.experiment_trust_mode == FEASIBILITY_MODE)
            self.attestation_preflight_ns = time.perf_counter_ns()-preflight_started
            if checked.mode != self.experiment_trust_mode:
                raise ProtocolRejectedError('attestation mode mismatch')
            self._qvl_session = checked
        else:
            self.attestation_preflight_ns = None
        self._kgc_key, self._do_key, self._admin_key = (new_private_key() for _ in range(3))
        self._k_rev = secrets.token_bytes(32)
        pp, msk = setup_algebra_core(self.crypto, c_max)
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            response = self.client.test_bootstrap(self.sys_id, self._k_rev,
                public_key_bytes(self._kgc_key), self.namespace, pp, self.crypto,
                self.clock.now())
            if response[0] != 'MYABE08-SGX-DEBUG-BOOT-OK':
                raise ProtocolRejectedError('TEST bootstrap rejected')
            self._cap_public, ack_public = response[1:3]
        else:
            self._cap_key, self._ack_key, self._root_key = (
                new_private_key() for _ in range(3))
            self._cap_public = public_key_bytes(self._cap_key)
            ack_public = public_key_bytes(self._ack_key)
            self._k_tok = secrets.token_bytes(32)
            self._sealing = EmulatedSealingService(secrets.token_bytes(32), self.crypto)
            self._registry = CredentialVersionRegistry()
            self._challenges = EmulatedChallengeStore()
            self._issue_store = TEEIssueStore()
            rev_store = EmulatedPersistentRevocationStore(
                self.state_path.with_suffix('.rev'), secrets.token_bytes(32), self.sys_id)
            head_store = EmulatedPersistentCurrentHeadStore(
                self.state_path.with_suffix('.head'), secrets.token_bytes(32), rev_store.load())
            self._rev_engine = TEERevocationEngine(rev_store, self._k_rev,
                public_key_bytes(self._kgc_key), self._ack_key)
            self._coordinator = LinearizedCurrentHeadCoordinator(rev_store.load(),
                ack_public, head_store)
            self._enclave = EmulatedAnonymousAuthorizationEnclave(
                coordinator=self._coordinator, clock=self.clock,
                revocation_engine=self._rev_engine)
        self._cert = issue_do_certificate(self._kgc_key, self.sys_id,
            self.namespace, public_key_bytes(self._do_key), validity)
        self._manager = KGCRevocationManager(self.sys_id, self._k_rev,
            public_key_bytes(self._admin_key), self._kgc_key, ack_public,
            EmulatedPersistentKGCStateStore(self.state_path,
                secrets.token_bytes(32), self.sys_id))
        self._pp, self._msk = pp, msk
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            self._instance = self.client.health()[3]
        self._rev_version = 0
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            self.metadata = dict(checked.metadata,
                CurrentHeadMode=CURRENT_HEAD_MODE,
                QVLApiReturn=checked.evaluation.api_return,
                CollateralExpirationStatus=checked.evaluation.collateral_expiration_status,
                MRENCLAVE=checked.checked_quote.fields.mrenclave.hex(),
                MRSIGNER=checked.checked_quote.fields.mrsigner.hex())
        else:
            self.metadata = dict(TEEProfile=EMULATED_TEE_PROFILE,
                ExperimentTrustMode=EMULATED_TEST_MODE,
                CurrentHeadMode=CURRENT_HEAD_MODE,
                RemoteAttestation='NOT_APPLICABLE')
        if self.component_allocation == 'ROW':
            self.metadata['InternalAblation'] = 'MYABE08_NO_OCCURRENCE_REUSE_V1'
        self._ready = True
        self._end('Setup', started)
        return PublicSetup(pp, msk, self.metadata.copy())

    def KeyGen(self, *, uid: str, attributes: tuple, auth_public_key: bytes,
               validity: Validity):
        started = self._start(); self._require_ready()
        if (type(attributes) is not tuple or not attributes or
                any(getattr(item, 'namespace', None) != self.namespace for item in attributes)):
            raise ContractError('credential namespace mismatch')
        base, recovery = keygen_algebra_core(self._pp, self._msk, self.crypto)
        credential = issue_credential(self._kgc_key, self.sys_id, uid,
            tuple(sorted(attributes)), validity, 1, auth_public_key)
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            session = self.client.open_test_session(self.sys_id, 'KGC')
            from .real_tee.messages import encode_registration
            blob = SealedUserBlob(self.client.register_test_user(session,
                session.send(encode_registration(credential, base, self.crypto))))
        else:
            private = UserBaseState(self.sys_id, credential.uid, base.mu,
                base.k0, credential_digest(credential),
                credential.credential_version, SCHEMA_VERSION,
                EMULATED_TEE_PROFILE)
            blob = self._sealing.seal(private)
            self._registry.register(credential)
        self._manager.register(uid)
        self._end('KeyGen', started)
        return PublicUser(credential, recovery, blob)

    def Encrypt(self, *, message: bytes, policy: PolicyInput,
                context: PolicyContext, data_id: bytes):
        # Reject unsupported messages before any SGX, AF or signing work.
        if type(message) is not bytes or not message:
            raise ContractError('UnsupportedMessage: nonempty bytes required')
        started = self._start(); self._require_ready()
        if type(policy) is not PolicyInput or type(context) is not PolicyContext:
            raise ContractError('PolicyInput and PolicyContext required')
        if context.sys_id != self.sys_id or context.ctx_priv != compute_ctx_priv(
                self.sys_id, context.policy_context_id, context.policy_version):
            raise ContractError('policy context mismatch')
        matrix = LSSSMatrix(policy.matrix, self.crypto.scalar_order,
            len(policy.matrix), len(policy.matrix[0]))
        if len(policy.row_labels) != matrix.ell:
            raise ContractError('policy label count mismatch')
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            session = self.client.open_test_session(self.sys_id, 'DO')
        else:
            session, server = self._emulated_channel()
        raw = encode_policy_labels(policy.row_labels)
        proof = sign_do_policy_proof(self._do_key, context, raw, session.binding)
        policy_token_started = time.perf_counter_ns()
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            tokens = self.client.policy_tokenize(session, self._cert, proof,
                context, session.send(raw))
        else:
            tokens = self._enclave.tokenize_policy_emulated(session.send(raw),
                server, certificate=self._cert, do_proof=proof, context=context,
                expected_namespace=self.namespace,
                kgc_public_key=public_key_bytes(self._kgc_key),
                k_tok=self._k_tok, backend=self.crypto)
        policy_token_ns = time.perf_counter_ns() - policy_token_started
        entries, _ = prepare_policy_rows(matrix, tokens, self._pp.c_max)
        af_header = make_af_header(matrix, tokens, context, self._pp.c_max,
                                   self.crypto)
        af_started = time.perf_counter_ns()
        from .metrics import AFMetrics
        af_metrics = AFMetrics()
        af = ProtectedPayloadAF().build(entries, header=af_header,
                                        ctx_af=compute_ctx_af(af_header),
                                        metrics=af_metrics)
        af_build_ns = time.perf_counter_ns() - af_started
        core_started = time.perf_counter_ns()
        core = encrypt_algebra_core(self._pp, matrix, tokens, self.crypto,
            component_allocation=self.component_allocation)
        encrypt_core_ns = time.perf_counter_ns() - core_started
        publication_started = time.perf_counter_ns()
        publication_stages = {}
        ct = build_publication(core, af, af_header, context, data_id, message,
            self._do_key, self._cert, self.crypto, tee_profile_id=self.backend_id,
            component_allocation=self.component_allocation,
            stage_timings_ns=publication_stages)
        publication_total_ns = time.perf_counter_ns() - publication_started
        self.encrypt_breakdown_ns.append(dict(policy_token_ns=policy_token_ns,
            af_build_ns=af_build_ns, encrypt_core_ns=encrypt_core_ns,
            dem_encrypt_ns=publication_stages['dem_encrypt_ns'],
            publication_sign_ns=publication_stages['publication_sign_ns'],
            publication_other_ns=max(0, publication_total_ns -
                publication_stages['dem_encrypt_ns'] -
                publication_stages['publication_sign_ns']),
            seed_retry_count=af_metrics.peel_failures))
        self._end('Encrypt', started)
        return ct

    def Rev(self, *, uid: str, operation: str):
        started = self._start(); self._require_ready()
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            session = self.client.open_test_session(self.sys_id, 'KGC')
        else:
            session, self._pending_rev_server = self._emulated_channel('REV')
        command = sign_management_command(self._admin_key, self.sys_id, uid,
                                          operation, self._manager.version)
        update = self._manager.rev(uid, operation, command, session)
        self._pending_rev_session = session
        self._end('Rev', started)
        return update

    def RevStateUpt(self, update):
        started = self._start(); self._require_ready()
        session = getattr(self, '_pending_rev_session', None)
        if session is None or self._manager.pending is None or update != self._manager.pending.protected:
            raise ProtocolRejectedError('RevStateUpt requires the exact pending update')
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            ack = self.client.rev_state_update(session, update)
            self._manager.commit_ack(ack, SgxHeadRpcProxy(self.client))
        else:
            ack = self._rev_engine.rev_state_upt(update, self._pending_rev_server)
            self._manager.commit_ack(ack, self._coordinator)
        self._pending_rev_session = None
        self._rev_version = self._manager.version
        self._end('RevStateUpt', started)
        return ack

    def TEEAuthorize(self, *, user: PublicUser, ciphertext, auth_private_key,
                     expiry: int):
        started = self._start(); self._require_ready()
        if _public_profile(ciphertext, self.crypto) != self.backend_id:
            raise UnsupportedProfileError('ciphertext/backend profile mismatch')
        self._require_allocation(ciphertext)
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            session = self.client.open_test_session(self.sys_id, 'DU')
        else:
            session, server = self._emulated_channel()
        request = make_emulated_host_request(ciphertext, self.crypto,
                                             session, expiry)
        proof = sign_possession(auth_private_key, self.sys_id, session.binding,
                                request.header_digest, request.request_nonce)
        record = session.send(encode_private_ingress(user.credential,
                                                     user.blob, proof))
        rpc_started = time.perf_counter_ns()
        if self.backend_id == SGX_DEBUG_GRAMINE_V1:
            auth, pairings, observed_timings = self.client.authorize_instrumented(
                session, ciphertext, request, record, self.crypto)
        else:
            from .metrics import ProtocolOperationCounts
            observed = ProtocolOperationCounts()
            auth = self._enclave.authorize_with_state_coordinator(
                ciphertext, request, record, server,
                backend=self.crypto, algebra_pp=self._pp,
                kgc_public_key=public_key_bytes(self._kgc_key),
                cap_private_key=self._cap_key, k_tok=self._k_tok,
                registry=self._registry, sealing_service=self._sealing,
                expected_namespace=self.namespace,
                issue_store=self._issue_store, metrics=observed)
            pairings = observed.t0_pairings
            observed_timings = {name:value for name,value in
                observed.stage_timings_ns.items() if name!='enclave_total_ns'}
        rpc_finished = time.perf_counter_ns()
        du_state = DURequestState.from_host_request(request)
        du_state.verify_response_binding(request, auth)
        if pairings != 1:
            raise ProtocolRejectedError('TEE pairing invariant failed')
        finished = time.perf_counter_ns()
        breakdown = dict(
            host_pre_rpc_ns=rpc_started-started,
            rpc_roundtrip_ns=rpc_finished-rpc_started if
                self.backend_id == SGX_DEBUG_GRAMINE_V1 else None,
            host_post_rpc_ns=finished-rpc_finished,
            rpc_send_ns=None, enclave_total_ns=None,
            credential_verify_ns=None, revset_lookup_ns=None,
            state_coordination_ns=None,
            tokenization_ns=None, rerandomization_ns=None,
            t0_pairing_ns=None, cap_sign_ns=None, rpc_receive_ns=None)
        breakdown.update(observed_timings)
        if self.backend_id == SGX_DEBUG_GRAMINE_V1 and any(
                breakdown[name] is None for name in (
                    'rpc_send_ns','rpc_receive_ns','enclave_total_ns',
                    'credential_verify_ns','revset_lookup_ns','tokenization_ns',
                    'state_coordination_ns','rerandomization_ns',
                    't0_pairing_ns','cap_sign_ns')):
            raise ProtocolRejectedError('SGX timing instrumentation incomplete')
        self.authorize_breakdown_ns.append(breakdown)
        self._end('TEEAuthorize', started)
        return PublicAuth(auth, request, du_state, pairings)

    def workload_metadata(self, partial: PublicPartial, *, policy_shape: str):
        """Public dimensions and trust labels only; no user/private row labels."""
        if type(partial) is not PublicPartial or type(policy_shape) is not str:
            raise ContractError('partial and policy shape required')
        ct = partial.ciphertext
        return dict(ell=len(ct.matrix), d=len(ct.matrix[0]),
            u=ct.header.af_header.distinct_tokens,
            N=len(partial.public_auth.authorization.bundle.items),
            cmax=ct.header.c_max, J=len(partial.candidate_rows),
            k=len(partial.reconstruction_rows), tI=len(partial.occurrence_slots),
            policy_shape=policy_shape,
            repeat_count=len(ct.matrix)-ct.header.af_header.distinct_tokens,
            TEEProfile=self.backend_id,
            ExperimentTrustMode=self.experiment_trust_mode,
            QVLResult=self.metadata.get('QVLResult', 'NOT_APPLICABLE'),
            CurrentHeadMode=self.current_head_mode,
            ComponentAllocation=self.component_allocation)

    def Transform(self, *, ciphertext, public_auth: PublicAuth):
        started = self._start(); self._require_ready()
        if _public_profile(ciphertext, self.crypto) != self.backend_id:
            raise UnsupportedProfileError('ciphertext/backend profile mismatch')
        self._require_allocation(ciphertext)
        if type(public_auth) is not PublicAuth:
            raise ContractError('PublicAuth required')
        public_auth.du_state.verify_response_binding(public_auth.request,
                                                     public_auth.authorization)
        counts = AlgebraOperationCounts()
        transform_stages = {}
        transformed = csp_transform_verified(public_auth.authorization,
            ciphertext, self._pp, self.crypto, self._cap_public,
            public_key_bytes(self._kgc_key), self.namespace, self.clock,
            self._csp_state, counts=counts, stage_timings_ns=transform_stages)
        expected = 1 + len(transformed.occurrence_slots)
        if counts.pairing_terms != expected:
            raise ProtocolRejectedError('CSP pairing invariant failed')
        partial = PublicPartial(ciphertext, public_auth, transformed.t_a,
            transformed.candidate_rows, transformed.reconstruction_rows,
            transformed.occurrence_slots, counts.pairing_terms)
        self.transform_breakdown_ns.append(transform_stages)
        self._end('Transform', started)
        return partial

    def FinalDec(self, *, partial: PublicPartial, recovery_key):
        started = self._start(); self._require_ready()
        if type(partial) is not PublicPartial:
            raise ContractError('PublicPartial required')
        ct, public_auth = partial.ciphertext, partial.public_auth
        if _public_profile(ct, self.crypto) != self.backend_id:
            raise UnsupportedProfileError('ciphertext/backend profile mismatch')
        self._require_allocation(ct)
        public_auth.du_state.verify_response_binding(public_auth.request,
                                                    public_auth.authorization)
        if public_auth.request.header_digest != header_digest(ct.header, self.crypto):
            raise ProtocolRejectedError('request/ciphertext mismatch')
        verify_publication(ct, self.crypto, public_key_bytes(self._kgc_key),
                           self.namespace, self.clock)
        verify_capability(public_auth.authorization, ct, self.crypto,
                          self._cap_public, self.clock)
        crypto_started = time.perf_counter_ns()
        _, recovered = finaldec_algebra_core(
            public_auth.authorization.bundle.t0_q, partial.t_a,
            recovery_key, self.crypto)
        finaldec_crypto_ns = time.perf_counter_ns() - crypto_started
        dem_started = time.perf_counter_ns()
        plaintext = dem_decrypt(compute_ctx_ct(ct.header, self.crypto),
            self.crypto.serialize_gt(recovered), DEMCiphertext(
                ct.dem_nonce, ct.encrypted_message))
        dem_decrypt_ns = time.perf_counter_ns() - dem_started
        self.finaldec_breakdown_ns.append(dict(
            finaldec_crypto_ns=finaldec_crypto_ns,
            dem_decrypt_ns=dem_decrypt_ns))
        self._end('FinalDec', started)
        return plaintext
