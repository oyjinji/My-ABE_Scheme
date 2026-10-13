"""TEST-only current-state coordinator and emulated protocol bootstrap."""
from contextlib import contextmanager
import secrets
import threading

from core.myabe08.af import ProtectedPayloadAF,compute_ctx_af
from core.myabe08.algebra import (AlgebraOperationCounts,setup_algebra_core,
    keygen_algebra_core,encrypt_algebra_core,finaldec_algebra_core)
from core.myabe08.attestation import EmulatedChallengeStore,issue_emulated_evidence
from core.myabe08.capability import csp_transform_verified
from core.myabe08.channel import (establish_emulated_channel,x25519_private_new,
                                   x25519_public_bytes)
from core.myabe08.credential import (CredentialVersionRegistry,credential_digest,
    encode_private_ingress,issue_credential,sign_possession)
from core.myabe08.crypto import BLS12381Backend,compute_ctx_priv,dem_decrypt,DEMCiphertext
from core.myabe08.errors import StateSynchronizationError
from core.myabe08.lsss import LSSSMatrix,prepare_policy_rows
from core.myabe08.metrics import ProtocolOperationCounts
from core.myabe08.publication import (build_publication,compute_ctx_ct,
    issue_do_certificate,make_af_header)
from core.myabe08.sealing import EmulatedSealingService,SCHEMA_VERSION
from core.myabe08.signing import new_private_key,public_key_bytes
from core.myabe08.state import CSPRequestState,CurrentHeadPermit,DURequestState,TEEIssueStore
from core.myabe08.tee import (EmulatedAnonymousAuthorizationEnclave,
    encode_policy_labels,make_emulated_host_request,sign_do_policy_proof)
from core.myabe08.types import Attribute,PolicyContext,UserBaseState,Validity

SYS_ID=b'MYABE08-PROTOCOL-TEST'
MEASUREMENT=b'M'*32
CTX_ID=b'C'*32


class DeterministicTestClock:
    def __init__(self,now=1000): self.value=now
    def now(self): return self.value


class TestCurrentStateCoordinator:
    """Only under tests/: does not model RevSet or real current-head sync."""
    __test__=False
    def __init__(self,mode='ACTIVE',version=7):
        self.mode=mode;self.version=version
        self._lock=threading.Lock();self.commits=[]
    @contextmanager
    def authorization_transaction(self,*,sys_id,fresh_nonce):
        with self._lock:
            if self.mode=='UNAVAILABLE': raise StateSynchronizationError('TEST state unavailable')
            coordinator=self
            class Transaction:
                def current_head(self):
                    return CurrentHeadPermit(sys_id,fresh_nonce,coordinator.version,
                        b'S'*32,b'T'*32,b'AUTHENTICATED-TEST-RECORD',
                        coordinator.mode=='ACTIVE')
                def commit_authorization(self,request_nonce,bundle_digest):
                    if coordinator.mode!='ACTIVE' or request_nonce!=fresh_nonce:
                        raise StateSynchronizationError('TEST state changed')
                    coordinator.commits.append((request_nonce,bundle_digest))
            yield Transaction()


def channel_pair(root_private,challenge_store,*,challenge=None,session_id=None,
                 measurement=MEASUREMENT,security_version=3,purpose='DU'):
    challenge=secrets.token_bytes(32) if challenge is None else challenge
    session_id=secrets.token_bytes(32) if session_id is None else session_id
    server_private=x25519_private_new();client_private=x25519_private_new()
    evidence=issue_emulated_evidence(root_private,SYS_ID,measurement,security_version,
                     challenge,x25519_public_bytes(server_private),session_id)
    client,server=establish_emulated_channel(client_private,server_private,evidence,
        public_key_bytes(root_private),SYS_ID,MEASUREMENT,2,challenge,challenge_store,
        purpose=purpose)
    return client,server,evidence,client_private,server_private


def bootstrap(*,labels=('A','B'),rows=((1,1),(0,-1)),user_labels=('A','B'),
              c_max=2,state_mode='ACTIVE',clock=None):
    clock=DeterministicTestClock() if clock is None else clock
    coordinator=TestCurrentStateCoordinator(state_mode)
    backend=BLS12381Backend(SYS_ID)
    kgc,do,cap,auth,root=(new_private_key() for _ in range(5))
    k_tok=secrets.token_bytes(32);k_seal=secrets.token_bytes(32)
    pp,msk=setup_algebra_core(backend,c_max)
    base,recovery=keygen_algebra_core(pp,msk,backend)
    validity=Validity(100,2000)
    cert=issue_do_certificate(kgc,SYS_ID,'ns',public_key_bytes(do),validity)
    attrs=tuple(sorted(Attribute('ns','label',x) for x in user_labels))
    credential=issue_credential(kgc,SYS_ID,'PRIVATE-UID',attrs,validity,1,public_key_bytes(auth))
    registry=CredentialVersionRegistry();registry.register(credential)
    sealing=EmulatedSealingService(k_seal,backend)
    private_base=UserBaseState(SYS_ID,credential.uid,base.mu,base.k0,
        credential_digest(credential),credential.credential_version,
        SCHEMA_VERSION,'EMULATED_TEE_PROFILE')
    blob=sealing.seal(private_base)
    enclave=EmulatedAnonymousAuthorizationEnclave(coordinator=coordinator,clock=clock)
    challenges=EmulatedChallengeStore()
    do_client,do_server,do_evidence,_,_=channel_pair(root,challenges)
    ctx_priv=compute_ctx_priv(SYS_ID,CTX_ID,1)
    context=PolicyContext(SYS_ID,CTX_ID,1,ctx_priv)
    policy_labels=tuple(Attribute('ns','label',x) for x in labels)
    raw_labels=encode_policy_labels(policy_labels)
    do_record=do_client.send(raw_labels)
    do_proof=sign_do_policy_proof(do,context,raw_labels,do_client.binding)
    tokens=enclave.tokenize_policy_emulated(do_record,do_server,certificate=cert,
        do_proof=do_proof,context=context,expected_namespace='ns',
        kgc_public_key=public_key_bytes(kgc),k_tok=k_tok,backend=backend)
    matrix=LSSSMatrix(tuple(tuple(r) for r in rows),backend.scalar_order,len(rows),len(rows[0]))
    entries,ranks=prepare_policy_rows(matrix,tokens,c_max)
    af_header=make_af_header(matrix,tokens,context,c_max,backend)
    ctx_af=compute_ctx_af(af_header)
    index=ProtectedPayloadAF().build(entries,header=af_header,ctx_af=ctx_af)
    core=encrypt_algebra_core(pp,matrix,tokens,backend)
    plaintext=b'MYABE08 Phase3B nonempty TEST message'
    publication=build_publication(core,index,af_header,context,b'DATA-ID',
                                  plaintext,do,cert,backend)
    du_client,du_server,du_evidence,_,_=channel_pair(root,challenges)
    request=make_emulated_host_request(publication,backend,du_client,1500)
    du_request_state=DURequestState.from_host_request(request)
    proof=sign_possession(auth,SYS_ID,du_client.binding,request.header_digest,
                          request.request_nonce)
    private_record=du_client.send(encode_private_ingress(credential,blob,proof))
    issue_store=TEEIssueStore();csp_state=CSPRequestState();metrics=ProtocolOperationCounts()
    return locals()


def authorize(env,**overrides):
    x=dict(env,**overrides)
    return x['enclave'].authorize_with_state_coordinator(
        x['publication'],x['request'],x['private_record'],x['du_server'],
        backend=x['backend'],algebra_pp=x['pp'],kgc_public_key=public_key_bytes(x['kgc']),
        cap_private_key=x['cap'],k_tok=x['k_tok'],registry=x['registry'],
        sealing_service=x['sealing'],expected_namespace='ns',
        issue_store=x['issue_store'],metrics=x['metrics'])


def complete(env,authz):
    x=env
    x['du_request_state'].verify_response_binding(x['request'],authz)
    csp_counts=AlgebraOperationCounts()
    transformed=csp_transform_verified(authz,x['publication'],x['pp'],x['backend'],
        public_key_bytes(x['cap']),public_key_bytes(x['kgc']),'ns',x['clock'],
        x['csp_state'],counts=csp_counts,metrics=x['metrics'])
    quotient,recovered=finaldec_algebra_core(authz.bundle.t0_q,transformed.t_a,
                                              x['recovery'],x['backend'])
    ctx_ct=compute_ctx_ct(x['publication'].header,x['backend'])
    message=dem_decrypt(ctx_ct,x['backend'].serialize_gt(recovered),
        DEMCiphertext(x['publication'].dem_nonce,x['publication'].encrypted_message))
    return message,transformed,csp_counts,recovered
