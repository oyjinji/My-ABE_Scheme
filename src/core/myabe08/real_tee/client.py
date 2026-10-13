"""Host transport adapter for explicit SGX DEBUG TEST integration only."""
from dataclasses import dataclass
import secrets

from ..channel import x25519_private_new,x25519_public_bytes
from ..encoding import UInt64,UInt32,encode,decode
from ..errors import AuthenticationError,ContractError
from ..metrics import AUTH_STAGE_TIMING_FIELDS
from ..profile import SGX_DEBUG_GRAMINE_V1
from ..revocation import ack_wire,parse_ack,parse_record,record_wire
from ..tee import EmulatedHostRequest
from .messages import (decode_authorization,encode_certificate,encode_context,
    encode_public_parameters,encode_publication)
from .rpc import (call,HEALTH,PROFILE_INFO,DEBUG_TEST_BOOTSTRAP,OPEN_TEST_SESSION,
    POLICY_TOKENIZE,TEST_REGISTER_USER,USER_AUTHORIZE,REV_STATE_UPDATE,
    TEST_COMMIT_HEAD,TEST_SHUTDOWN,RA_QUOTE_PROBE,RA_SESSION_OPEN,
    RA_SESSION_ACTIVATE,RA_DUMMY_PROVISION,TEST_STATE_OBSERVE,TEST_STATE_FAULT)
from .session import open_client_session
from .attested_session import (channel_endpoint,FEASIBILITY_MODE,STRICT_MODE)
from .qvl_policy import (FEASIBILITY_LABEL,decide_policy,verify_real_quote,
                         QvlCheckedNonTerminalQuote,StrictVerifiedSgxQuote)


@dataclass
class QuoteBoundTestSession:
    """TEST-only channel state; not a canonical attested TEE profile."""
    session_id: bytes
    challenge: bytes
    endpoint: object
    evaluation: object
    checked_quote: object
    decision: object
    mode: str
    dummy_sent_count: int = 0

    @property
    def metadata(self):
        return dict(TEEProfile=SGX_DEBUG_GRAMINE_V1,
            ExperimentTrustMode=FEASIBILITY_LABEL if self.mode==FEASIBILITY_MODE else '',
            RemoteAttestation='QVL_COMPLETED_NONTERMINAL' if
                self.mode==FEASIBILITY_MODE else 'QVL_COMPLETED_CURRENT_TCB',
            QVLResult='SGX_QL_QV_RESULT_OUT_OF_DATE' if
                self.mode==FEASIBILITY_MODE else 'SGX_QL_QV_RESULT_OK',
            StrictRA2='BLOCKED_BY_TCB_POLICY' if
                self.mode==FEASIBILITY_MODE else 'PASS',
            EnclaveDebug=self.checked_quote.fields.debug,
            INSECURE_TEST_OVERRIDE_USED=self.mode==FEASIBILITY_MODE)


class SgxDebugClient:
    """No claim of attested channel or production secret transport."""
    def __init__(self,address=('127.0.0.1',38508)):
        self.address=address
        self._seen_quote_digests=set()

    def health(self):
        return call(self.address,HEALTH,('MYABE08-HEALTH-V1',))

    def profile_info(self):
        return call(self.address,PROFILE_INFO,('MYABE08-PROFILE-V1',))

    def quote_diagnostic(self,sys_id,challenge):
        """Unverified TEST quote observation; never enables provisioning."""
        return call(self.address,RA_QUOTE_PROBE,
                    ('MYABE08-RA-QUOTE-PROBE-V1',sys_id,challenge))

    def open_quote_bound_test_session(self,sys_id,identity_policy,*,
                                      allow_outdated_debug_feasibility=False):
        """QVL -> TCB policy -> identity/DEBUG/binding -> X25519 TEST channel."""
        challenge=secrets.token_bytes(32)
        session_id=secrets.token_bytes(32)
        result=call(self.address,RA_SESSION_OPEN,
            ('MYABE-RA-SESSION-OPEN-V1',sys_id,challenge,session_id))
        if (type(result) is not tuple or len(result)!=5 or
                result[0]!='MYABE-RA-SESSION-QUOTE-V1' or result[1]!=session_id):
            raise ContractError('RA quote response mismatch')
        enclave_public,reported_data,quote=result[2:]
        # These fields remain untrusted until the actual Intel QVL call succeeds.
        evaluation,checked=verify_real_quote(quote)
        if checked is None:
            raise AuthenticationError('QVL did not authenticate a nonterminal quote')
        decision=decide_policy(evaluation,
            allow_outdated_debug_feasibility=allow_outdated_debug_feasibility,
            enclave_debug=checked.fields.debug)
        if not (decision.strict_accepted or decision.feasibility_accepted):
            raise AuthenticationError(decision.reason)
        if not isinstance(checked,(StrictVerifiedSgxQuote,QvlCheckedNonTerminalQuote)):
            raise AuthenticationError('RA quote type rejected')
        if not checked.check_identity(identity_policy):
            raise AuthenticationError('RA identity/DEBUG policy rejected')
        if reported_data!=checked.fields.report_data:
            raise AuthenticationError('RA report_data response substitution')
        checked.check_binding(sys_id,challenge,enclave_public)
        if checked.quote_digest in self._seen_quote_digests:
            raise AuthenticationError('RA old quote replay')
        self._seen_quote_digests.add(checked.quote_digest)
        private=x25519_private_new()
        client_public=x25519_public_bytes(private)
        mode=STRICT_MODE if decision.strict_accepted else FEASIBILITY_MODE
        activated=call(self.address,RA_SESSION_ACTIVATE,
            ('MYABE-RA-SESSION-ACTIVATE-V1',session_id,client_public,
             checked.quote_digest,UInt64(evaluation.qv_result),mode))
        if (type(activated) is not tuple or len(activated)!=3 or
                activated[:2]!=('MYABE-RA-SESSION-READY-V1',session_id)):
            raise ContractError('RA activation response mismatch')
        endpoint=channel_endpoint(private,enclave_public,enclave_side=False,
            sys_id=sys_id,session_id=session_id,challenge=challenge,
            quote_digest=checked.quote_digest,qv_result=evaluation.qv_result,
            mode=mode)
        ready=decode(endpoint.receive(parse_record(activated[2])))
        if ready!=('MYABE-RA-CHANNEL-READY',session_id):
            raise AuthenticationError('RA channel key confirmation failed')
        return QuoteBoundTestSession(session_id,challenge,endpoint,evaluation,
                                     checked,decision,mode)

    def provision_random_test_dummy(self,session):
        """Send exactly one fresh random 32-byte dummy through feasibility AEAD."""
        if type(session) is not QuoteBoundTestSession or session.mode!=FEASIBILITY_MODE:
            raise AuthenticationError('strict session cannot provision TEST dummy')
        if session.dummy_sent_count:
            raise ContractError('TEST dummy already sent')
        request_id=secrets.token_bytes(16)
        dummy=secrets.token_bytes(32)
        protected=record_wire(session.endpoint.send(encode(
            ('MYABE-RA-DUMMY-PROVISION',request_id,dummy))))
        result=call(self.address,RA_DUMMY_PROVISION,
            ('MYABE-RA-DUMMY-PROVISION-V1',session.session_id,protected))
        if (type(result) is not tuple or len(result)!=3 or
                result[:2]!=('MYABE-RA-DUMMY-RESPONSE-V1',session.session_id)):
            raise ContractError('RA dummy response mismatch')
        acknowledgement=decode(session.endpoint.receive(parse_record(result[2])))
        if acknowledgement!=('PROVISION_TEST_OK',UInt32(32),request_id):
            raise AuthenticationError('RA dummy acknowledgement rejected')
        session.dummy_sent_count+=1
        return acknowledgement[0],acknowledgement[1].value,acknowledgement[2]

    def test_bootstrap(self,sys_id,k_rev,kgc_public,namespace,pp,backend,test_now):
        return call(self.address,DEBUG_TEST_BOOTSTRAP,
            ('MYABE08-SGX-DEBUG-TEST-BOOT-V1',sys_id,k_rev,kgc_public,namespace,
             encode_public_parameters(pp,backend),UInt64(test_now),'TEST_CURRENT_HEAD'))

    def open_test_session(self,sys_id,purpose):
        private=x25519_private_new()
        challenge=secrets.token_bytes(32);session_id=secrets.token_bytes(32)
        result=call(self.address,OPEN_TEST_SESSION,
            ('MYABE08-OPEN-TEST-SESSION',purpose,x25519_public_bytes(private),
             challenge,session_id))
        if (type(result) is not tuple or len(result)!=3 or
                result[:2]!=('MYABE08-TEST-SESSION',session_id)):
            raise ContractError('TEST session response mismatch')
        return open_client_session(sys_id,purpose,private,result[2],challenge,session_id)

    def register_test_user(self,session,encrypted_record):
        result=call(self.address,TEST_REGISTER_USER,
            ('MYABE08-TEST-REGISTER',session.binding.session_id,
             record_wire(encrypted_record)))
        if type(result) is not tuple or len(result)!=2 or result[0]!='MYABE08-SEALED-BLOB':
            raise ContractError('sealed blob response mismatch')
        return result[1]

    def policy_tokenize(self,session,certificate,proof,context,encrypted_record):
        result=call(self.address,POLICY_TOKENIZE,
            ('MYABE08-POLICY-TOKENIZE',session.binding.session_id,
             encode_certificate(certificate),proof,encode_context(context),
             record_wire(encrypted_record)))
        if type(result) is not tuple or len(result)!=2 or result[0]!='MYABE08-POLICY-TOKENS':
            raise ContractError('policy token response mismatch')
        return result[1]

    def authorize(self,session,publication,request,encrypted_record,backend):
        auth,pairings,_=self.authorize_instrumented(
            session,publication,request,encrypted_record,backend)
        return auth,pairings

    def authorize_instrumented(self,session,publication,request,encrypted_record,backend):
        if type(request) is not EmulatedHostRequest:
            raise ContractError('host request required')
        fields=(request.header_digest,request.ctx_priv,request.request_nonce,
                UInt64(request.expiry),request.session_id,request.challenge,
                UInt64(request.version_hint))
        transport={}
        result=call(self.address,USER_AUTHORIZE,
            ('MYABE08-USER-AUTHORIZE',session.binding.session_id,
             encode_publication(publication,backend),fields,record_wire(encrypted_record)),
             transport_timings_ns=transport)
        if (type(result) is not tuple or len(result)!=5 or
                result[0]!='MYABE08-SGX-AUTH-V1' or
                result[3]!='SGX_DEBUG_GRAMINE_V1' or
                type(result[4]) is not tuple or
                len(result[4])!=len(AUTH_STAGE_TIMING_FIELDS) or
                any(type(value) is not UInt64 for value in result[4])):
            raise ContractError('SGX Auth response mismatch')
        stages=dict(zip(AUTH_STAGE_TIMING_FIELDS,
                        (value.value for value in result[4])))
        if sum(stages[name] for name in AUTH_STAGE_TIMING_FIELDS[1:])>stages['enclave_total_ns']:
            raise ContractError('SGX Auth timing consistency rejected')
        if (set(transport) != {'rpc_send_ns','rpc_receive_ns',
                              'rpc_send_bytes','rpc_receive_bytes'} or
            any(type(value) is not int or value < 0 for value in transport.values())):
            raise ContractError('RPC timing observation missing')
        return decode_authorization(result[1],backend),result[2].value,dict(stages,**transport)

    def rev_state_update(self,session,protected):
        result=call(self.address,REV_STATE_UPDATE,
            ('MYABE08-REV-STATE-UPDATE',session.binding.session_id,
             protected.protected_record))
        if type(result) is not tuple or len(result)!=2 or result[0]!='MYABE08-REV-ACK':
            raise ContractError('Ack response mismatch')
        return parse_ack(result[1])

    def commit_test_head(self,old_version,old_digest,ack):
        return call(self.address,TEST_COMMIT_HEAD,
            ('MYABE08-TEST-COMMIT-HEAD',UInt64(old_version),old_digest,ack_wire(ack)))

    def stop_test_service(self):
        return call(self.address,TEST_SHUTDOWN,('MYABE08-TEST-SHUTDOWN',))

    def observe_test_state(self):
        """TEST-only aggregate state counters; no handles or identifiers."""
        result=call(self.address,TEST_STATE_OBSERVE,('MYABE08-TEST-STATE-V1',))
        names=('rev_version','revset_count','revset_logical_bytes',
            'registration_state_count','registration_state_logical_bytes',
            'rejected_revset_lookup_ns','rejected_user_tokens_emitted',
            'rejected_t0_pairings','rejected_caps_emitted',
            'enclave_state_apply_ns','coordinator_commit_ns')
        if (type(result) is not tuple or len(result)!=len(names)+1 or
            result[0]!='MYABE08-TEST-STATE-V1' or
            any(type(value) is not UInt64 for value in result[1:])):
            raise ContractError('TEST state observation malformed')
        return dict(zip(names,(value.value for value in result[1:])))

    def test_state_fault(self, action):
        """Isolated Phase 5C negative test only; never a normal update path."""
        if action not in ('FREEZE_ON','FREEZE_OFF','HEAD_AHEAD_ON',
                          'HEAD_AHEAD_OFF','LOCAL_ROLLBACK'):
            raise ContractError('unknown TEST state fault')
        result=call(self.address,TEST_STATE_FAULT,
                    ('MYABE08-TEST-STATE-FAULT-V1',action))
        if result!=('MYABE08-TEST-STATE-FAULT-OK',action):
            raise ContractError('TEST state fault response mismatch')
        return True


class SgxHeadRpcProxy:
    """KGC-side TEST proxy; trusted freshness is not provided by this transport."""
    def __init__(self,client): self.client=client
    def commit_revocation(self,old_version,old_digest,ack):
        self.client.commit_test_head(old_version,old_digest,ack)
