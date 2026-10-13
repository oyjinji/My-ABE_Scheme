"""Measured fixed-entrypoint MYABE-08 SGX DEBUG trusted-control-plane service.

The only enabled bootstrap is explicit TEST mode. Socket/session encryption is
not remote attestation. No production credential, key or state should be sent.
"""
import hashlib
import os
import secrets
import socket
import traceback
from time import perf_counter_ns

from ..algebra import AlgebraPublicParameters
from ..capability import authorization_bytes
from ..credential import (CredentialVersionRegistry,credential_digest,
    credential_fields)
from ..crypto import BLS12381Backend
from ..encoding import UInt32,UInt64,encode,require_bytes
from ..errors import (AuthenticationError,ContractError,ProtocolRejectedError,
                      StateSynchronizationError)
from ..metrics import AUTH_STAGE_TIMING_FIELDS, ProtocolOperationCounts
from ..profile import MYABE08_ENCODING_V1,SGX_DEBUG_GRAMINE_V1
from ..publication import header_digest
from ..revocation import (EmulatedPersistentCurrentHeadStore,
    EmulatedPersistentRevocationStore,LinearizedCurrentHeadCoordinator,
    RevocationState,TEERevocationEngine,ack_wire,parse_ack,parse_record)
from ..revocation import state_digest
from ..signing import new_private_key,public_key_bytes,verify_canonical
from ..state import TEEIssueStore
from ..tee import (EmulatedAnonymousAuthorizationEnclave,EmulatedHostRequest)
from ..types import RevocationUpdate,UserBaseState
from .messages import (decode_certificate,decode_context,decode_public_parameters,
    decode_publication,decode_registration)
from .providers import (DebugTestTimeProvider,SgxResidentApplicationSealingProvider,
    new_internal_bundle)
from .rpc import (HEALTH,PROFILE_INFO,DEBUG_TEST_BOOTSTRAP,OPEN_TEST_SESSION,
    POLICY_TOKENIZE,TEST_REGISTER_USER,USER_AUTHORIZE,REV_STATE_UPDATE,
    TEST_COMMIT_HEAD,TEST_SHUTDOWN,RA_QUOTE_PROBE,RA_SESSION_OPEN,
    RA_SESSION_ACTIVATE,RA_DUMMY_PROVISION,TEST_STATE_OBSERVE,TEST_STATE_FAULT,
    read_request,write_response)
from .session import open_server_session
from .attestation import gramine_quote_probe
from .attested_session import AttestationSessionManager

ADDRESS=('127.0.0.1',38508)


def local_sgx_report():
    """Fail startup outside SGX; report fields are non-secret process evidence."""
    with open('/dev/attestation/my_target_info','rb') as inp:
        target=inp.read()
    with open('/dev/attestation/target_info','wb') as out:
        out.write(target)
    with open('/dev/attestation/user_report_data','wb') as out:
        out.write(secrets.token_bytes(64))
    with open('/dev/attestation/report','rb') as inp:
        report=inp.read()
    if len(report)!=432:
        raise StateSynchronizationError('SGX local report unavailable')
    flags=int.from_bytes(report[48:56],'little')
    if not flags&2:
        raise StateSynchronizationError('SGX DEBUG profile requires debug enclave')
    return report[64:96],report[128:160],flags


def _shape(value,length,tag):
    if type(value) is not tuple or len(value)!=length or value[0]!=tag:
        raise ContractError('RPC schema mismatch')
    return value


def _uint(value):
    if type(value) is not UInt64: raise ContractError('uint64 required')
    return value.value


class SgxDebugService:
    def __init__(self,*,test_mode=False):
        self.measurement,self.signer,self.flags=local_sgx_report()
        self.test_mode=test_mode
        self.ready=False
        self.stop=False
        self.last_reject_metrics=(0,0,0,0)
        self.last_state_apply_ns=0
        self.last_commit_ns=0
        self.test_head_disabled=False
        self.test_previous_state=None
        self.test_original_head=None
        self._seen_requests=set()
        self.sessions={}
        self.attestation_sessions=AttestationSessionManager()
        self.instance_id=secrets.token_bytes(16)
        self.t0_pairings_total=0

    def _require_ready(self):
        if not self.ready: raise StateSynchronizationError('state unavailable')

    def _session(self,session_id,purpose):
        require_bytes(session_id,'session ID',32)
        found=self.sessions.get(session_id)
        if found is None or found[0]!=purpose:
            raise AuthenticationError('TEST session unavailable')
        return found[1]

    def _bootstrap(self,value):
        if not self.test_mode or self.ready:
            raise StateSynchronizationError('TEST bootstrap unavailable')
        v=_shape(value,8,'MYABE08-SGX-DEBUG-TEST-BOOT-V1')
        _,sys_id,k_rev,kgc_public,namespace,pp_wire,time_value,head_mode=v
        require_bytes(sys_id,'SysID')
        require_bytes(k_rev,'TEST K_rev',32)
        require_bytes(kgc_public,'KGC public key',32)
        if not sys_id or type(namespace) is not str or not namespace:
            raise ContractError('bootstrap scope malformed')
        if head_mode!='TEST_CURRENT_HEAD':
            raise StateSynchronizationError('trusted current head not configured')
        backend=BLS12381Backend(sys_id)
        pp=decode_public_parameters(pp_wire,backend)
        clock=DebugTestTimeProvider(_uint(time_value))
        bundle=new_internal_bundle(sys_id,k_rev)
        base='/tmp/myabe08-sgx-debug-'+self.instance_id.hex()
        state_store=EmulatedPersistentRevocationStore(base+'.rev',bundle.k_state,sys_id)
        initial=state_store.load()
        head_store=EmulatedPersistentCurrentHeadStore(base+'.head',bundle.k_head,initial)
        ack_private=new_private_key()
        ack_public=public_key_bytes(ack_private)
        coordinator=LinearizedCurrentHeadCoordinator(initial,ack_public,head_store)
        engine=TEERevocationEngine(state_store,bundle.k_rev,kgc_public,ack_private)
        sealing=SgxResidentApplicationSealingProvider(bundle.k_seal,backend)
        enclave=EmulatedAnonymousAuthorizationEnclave(profile=SGX_DEBUG_GRAMINE_V1,
            coordinator=coordinator,clock=clock,revocation_engine=engine)
        self.sys_id,self.backend,self.pp,self.clock=sys_id,backend,pp,clock
        self.bundle,self.kgc_public,self.namespace=bundle,kgc_public,namespace
        self.registry=CredentialVersionRegistry()
        self.coordinator,self.engine,self.sealing=coordinator,engine,sealing
        self.enclave=enclave
        self.issue_store=TEEIssueStore()
        self.ready=True
        return ('MYABE08-SGX-DEBUG-BOOT-OK',public_key_bytes(bundle.sk_cap),
                ack_public,initial.state_digest,self.instance_id)

    def handle(self,message_type,value):
        if message_type==HEALTH:
            _shape(value,1,'MYABE08-HEALTH-V1')
            return ('MYABE08-HEALTH-V1',SGX_DEBUG_GRAMINE_V1,
                    UInt32(1 if self.ready else 0),self.instance_id,
                    UInt64(self.t0_pairings_total))
        if message_type==PROFILE_INFO:
            _shape(value,1,'MYABE08-PROFILE-V1')
            return ('MYABE08-PROFILE-V1',SGX_DEBUG_GRAMINE_V1,
                MYABE08_ENCODING_V1,'BLS12-381','py_ecc-8.0.0',UInt32(1),
                self.measurement,self.signer,UInt64(self.flags),
                public_key_bytes(self.bundle.sk_cap) if self.ready else b'')
        if message_type==DEBUG_TEST_BOOTSTRAP:
            return self._bootstrap(value)
        if message_type==RA_QUOTE_PROBE:
            if not self.test_mode:
                raise StateSynchronizationError('TEST quote probe unavailable')
            v=_shape(value,3,'MYABE08-RA-QUOTE-PROBE-V1')
            require_bytes(v[1],'RA SysID')
            require_bytes(v[2],'RA challenge',32)
            try:
                channel_public,report_data,quote=gramine_quote_probe(v[1],v[2])
            except OSError as exc:
                return ('MYABE08-RA-QUOTE-DIAGNOSTIC',UInt32(exc.errno or 0),
                        type(exc).__name__,UInt32(0))
            return ('MYABE08-RA-QUOTE-UNVERIFIED',channel_public,
                    report_data,quote)
        if message_type==RA_SESSION_OPEN:
            if not self.test_mode:
                raise StateSynchronizationError('RA TEST session unavailable')
            v=_shape(value,4,'MYABE-RA-SESSION-OPEN-V1')
            public,report_data,quote=self.attestation_sessions.open(v[1],v[2],v[3])
            return ('MYABE-RA-SESSION-QUOTE-V1',v[3],public,report_data,quote)
        if message_type==RA_SESSION_ACTIVATE:
            if not self.test_mode:
                raise StateSynchronizationError('RA TEST activation unavailable')
            v=_shape(value,6,'MYABE-RA-SESSION-ACTIVATE-V1')
            record=self.attestation_sessions.activate(v[1],v[2],v[3],
                                                       _uint(v[4]),v[5])
            return ('MYABE-RA-SESSION-READY-V1',v[1],record)
        if message_type==RA_DUMMY_PROVISION:
            if not self.test_mode:
                raise StateSynchronizationError('RA TEST dummy unavailable')
            v=_shape(value,3,'MYABE-RA-DUMMY-PROVISION-V1')
            record=self.attestation_sessions.provision_dummy(v[1],v[2])
            return ('MYABE-RA-DUMMY-RESPONSE-V1',v[1],record)
        if message_type==TEST_SHUTDOWN:
            if not self.test_mode: raise StateSynchronizationError('TEST shutdown unavailable')
            _shape(value,1,'MYABE08-TEST-SHUTDOWN')
            self.stop=True
            return ('MYABE08-STOPPING',)
        self._require_ready()
        if message_type==OPEN_TEST_SESSION:
            if not self.test_mode: raise StateSynchronizationError('TEST session unavailable')
            v=_shape(value,5,'MYABE08-OPEN-TEST-SESSION')
            _,purpose,client_public,challenge,session_id=v
            if session_id in self.sessions: raise ContractError('session ID reused')
            server_public,endpoint=open_server_session(self.sys_id,purpose,
                client_public,challenge,session_id)
            self.sessions[session_id]=(purpose,endpoint)
            return ('MYABE08-TEST-SESSION',session_id,server_public)
        if message_type==TEST_REGISTER_USER:
            if not self.test_mode: raise StateSynchronizationError('TEST registration unavailable')
            v=_shape(value,3,'MYABE08-TEST-REGISTER')
            endpoint=self._session(v[1],'KGC')
            credential,base=decode_registration(endpoint.receive(parse_record(v[2])),
                                                self.backend)
            if credential.sys_id!=self.sys_id:
                raise AuthenticationError('credential scope mismatch')
            verify_canonical(self.kgc_public,credential.signature,'MYABE-CRED',
                             *credential_fields(credential))
            now=self.clock.now()
            if not credential.validity.not_before<=now<credential.validity.not_after:
                raise AuthenticationError('credential validity rejected')
            user=UserBaseState(self.sys_id,credential.uid,base.mu,base.k0,
                credential_digest(credential),credential.credential_version,
                self.sealing.schema_version,SGX_DEBUG_GRAMINE_V1)
            opaque=self.sealing.seal(user).opaque
            self.registry.register(credential)
            return ('MYABE08-SEALED-BLOB',opaque)
        if message_type==POLICY_TOKENIZE:
            v=_shape(value,6,'MYABE08-POLICY-TOKENIZE')
            endpoint=self._session(v[1],'DO')
            cert=decode_certificate(v[2]);context=decode_context(v[4])
            tokens=self.enclave.tokenize_policy_emulated(parse_record(v[5]),endpoint,
                certificate=cert,do_proof=v[3],context=context,
                expected_namespace=self.namespace,kgc_public_key=self.kgc_public,
                k_tok=self.bundle.k_tok,backend=self.backend)
            return ('MYABE08-POLICY-TOKENS',tokens)
        if message_type==USER_AUTHORIZE:
            if self.test_head_disabled:
                raise StateSynchronizationError('TEST current head unavailable')
            enclave_started=perf_counter_ns()
            self.last_reject_metrics=(0,0,0,0)
            v=_shape(value,5,'MYABE08-USER-AUTHORIZE')
            endpoint=self._session(v[1],'DU')
            publication=decode_publication(v[2],self.backend)
            r=v[3]
            if type(r) is not tuple or len(r)!=7:
                raise ContractError('host request schema')
            request=EmulatedHostRequest(r[0],r[1],r[2],_uint(r[3]),r[4],r[5],
                                        _uint(r[6]))
            metrics=ProtocolOperationCounts()
            try:
                auth=self.enclave.authorize_with_state_coordinator(publication,request,
                    parse_record(v[4]),endpoint,backend=self.backend,algebra_pp=self.pp,
                    kgc_public_key=self.kgc_public,cap_private_key=self.bundle.sk_cap,
                    k_tok=self.bundle.k_tok,registry=self.registry,
                    sealing_service=self.sealing,expected_namespace=self.namespace,
                    issue_store=self.issue_store,metrics=metrics)
            except ProtocolRejectedError as exc:
                if str(exc)=='revoked':
                    self.last_reject_metrics=(metrics.stage_timings_ns.get('revset_lookup_ns',0),
                        metrics.user_token_prf_count,metrics.t0_pairings,
                        metrics.cap_signatures)
                raise
            self.t0_pairings_total+=metrics.t0_pairings
            auth_wire=authorization_bytes(auth,self.backend)
            stages=metrics.stage_timings_ns
            stages['enclave_total_ns']=perf_counter_ns()-enclave_started
            if (any(type(stages.get(name)) is not int or stages[name]<0
                    for name in AUTH_STAGE_TIMING_FIELDS) or
                    sum(stages[name] for name in AUTH_STAGE_TIMING_FIELDS[1:])>
                        stages['enclave_total_ns']):
                raise ContractError('TEST timing instrumentation invalid')
            return ('MYABE08-SGX-AUTH-V1',auth_wire,
                    UInt32(metrics.t0_pairings),SGX_DEBUG_GRAMINE_V1,
                    tuple(UInt64(stages[name]) for name in AUTH_STAGE_TIMING_FIELDS))
        if message_type==REV_STATE_UPDATE:
            v=_shape(value,3,'MYABE08-REV-STATE-UPDATE')
            endpoint=self._session(v[1],'KGC')
            started=perf_counter_ns()
            previous=self.engine.store.load() if self.test_mode else None
            ack=self.engine.rev_state_upt(RevocationUpdate(v[2]),endpoint)
            if self.test_mode and self.engine.store.load().rev_version>previous.rev_version:
                self.test_previous_state=previous
            self.last_state_apply_ns=perf_counter_ns()-started
            return ('MYABE08-REV-ACK',ack_wire(ack))
        if message_type==TEST_COMMIT_HEAD:
            if not self.test_mode: raise StateSynchronizationError('TEST head unavailable')
            v=_shape(value,4,'MYABE08-TEST-COMMIT-HEAD')
            old_version=_uint(v[1]);require_bytes(v[2],'old digest',32)
            started=perf_counter_ns()
            self.coordinator.commit_revocation(old_version,v[2],parse_ack(v[3]))
            self.last_commit_ns=perf_counter_ns()-started
            return ('MYABE08-HEAD-COMMITTED',UInt64(self.coordinator.version),
                    self.coordinator.digest)
        if message_type==TEST_STATE_OBSERVE:
            if not self.test_mode:
                raise StateSynchronizationError('TEST state observation unavailable')
            _shape(value,1,'MYABE08-TEST-STATE-V1')
            state=self.engine.store.load()
            values=(state.rev_version,state.revset._size(),
                len(encode(state.revset._canonical())),self.registry.count(),
                self.registry.logical_bytes())+self.last_reject_metrics+(
                self.last_state_apply_ns,self.last_commit_ns)
            return ('MYABE08-TEST-STATE-V1',)+tuple(UInt64(x) for x in values)
        if message_type==TEST_STATE_FAULT:
            if not self.test_mode:
                raise StateSynchronizationError('TEST fault unavailable')
            v=_shape(value,2,'MYABE08-TEST-STATE-FAULT-V1')
            action=v[1]
            if action=='FREEZE_ON':
                self.test_head_disabled=True
            elif action=='FREEZE_OFF':
                self.test_head_disabled=False
            elif action=='HEAD_AHEAD_ON':
                if self.test_original_head is not None:
                    raise StateSynchronizationError('TEST head fault already active')
                old=(self.coordinator.version,self.coordinator.digest)
                state=self.engine.store.load()
                if state.rev_version!=old[0] or state.state_digest!=old[1]:
                    raise StateSynchronizationError('TEST head baseline inconsistent')
                advanced=state_digest(self.sys_id,old[0]+1,state.revset)
                self.coordinator._head_store.save(old[0]+1,advanced,
                    expected_version=old[0],expected_digest=old[1],
                    predecessor_digest=old[1],update_digest=b'\x00'*32)
                self.coordinator.version,self.coordinator.digest=old[0]+1,advanced
                self.test_original_head=old
            elif action=='HEAD_AHEAD_OFF':
                if self.test_original_head is None:
                    raise StateSynchronizationError('TEST head fault absent')
                old=self.test_original_head
                self.coordinator._head_store.save(old[0],old[1],
                    expected_version=self.coordinator.version,
                    expected_digest=self.coordinator.digest,
                    predecessor_digest=b'\x00'*32,update_digest=b'\x00'*32)
                self.coordinator.version,self.coordinator.digest=old
                self.test_original_head=None
            elif action=='LOCAL_ROLLBACK':
                old=self.test_previous_state
                current=self.engine.store.load()
                if old is None or old.rev_version!=current.rev_version-1:
                    raise StateSynchronizationError('TEST rollback snapshot absent')
                self.engine.store.save(old,expected_version=current.rev_version)
            else:
                raise ContractError('unknown TEST state fault')
            return ('MYABE08-TEST-STATE-FAULT-OK',action)
        raise ContractError('unknown message type')

    def serve(self,address=ADDRESS):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(address);listener.listen(8)
            print('MYABE08_SGX_DEBUG_SERVICE_READY',os.getpid(),flush=True)
            while not self.stop:
                conn,_=listener.accept()
                with conn:
                    conn.settimeout(10)
                    try:
                        kind,request_id,value=read_request(conn)
                        if request_id in self._seen_requests:
                            raise ContractError('request ID replay')
                        self._seen_requests.add(request_id)
                        answer=self.handle(kind,value)
                        write_response(conn,kind,request_id,answer)
                    except (ContractError,AuthenticationError,ProtocolRejectedError,
                            StateSynchronizationError) as exc:
                        if 'kind' in locals() and 'request_id' in locals():
                            if isinstance(exc,StateSynchronizationError): code='STATE_UNAVAILABLE'
                            elif isinstance(exc,AuthenticationError): code='AUTH_FAILED'
                            elif isinstance(exc,ProtocolRejectedError) and str(exc)=='revoked':
                                code='REVOKED'
                            elif isinstance(exc,ProtocolRejectedError): code='AUTH_FAILED'
                            else: code='INVALID_REQUEST'
                            write_response(conn,kind,request_id,code,error=True)
                    except Exception as exc:
                        if self.test_mode:
                            frames=traceback.extract_tb(exc.__traceback__)
                            print('MYABE08_TEST_ERROR',type(exc).__name__,
                                  tuple((frame.name,frame.lineno) for frame in frames),
                                  flush=True)
                        if 'kind' in locals() and 'request_id' in locals():
                            write_response(conn,kind,request_id,'INTERNAL_ERROR',error=True)
                    finally:
                        # Do not retain identifiers from a previous malformed frame.
                        kind=request_id=None


def main():
    # The signed manifest fixes the entrypoint/argv and this non-secret TEST flag.
    test_mode=os.environ.get('MYABE08_SGX_DEBUG_TEST_MODE')=='1'
    service=SgxDebugService(test_mode=test_mode)
    service.serve()


if __name__=='__main__':
    main()
