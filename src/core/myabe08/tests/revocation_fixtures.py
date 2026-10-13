"""TEST-only emulated revocation control plane; no hardware claims."""
import secrets

from core.myabe08.attestation import EmulatedChallengeStore
from core.myabe08.metrics import RevocationOperationCounts
from core.myabe08.revocation import (ACTIVATE, REVOKE, EmulatedPersistentRevocationStore,
    EmulatedPersistentCurrentHeadStore, EmulatedPersistentKGCStateStore,
    KGCRevocationManager,
    LinearizedCurrentHeadCoordinator, TEERevocationEngine,
    sign_management_command)
from core.myabe08.signing import new_private_key, public_key_bytes
from core.myabe08.tee import EmulatedAnonymousAuthorizationEnclave
from core.myabe08.tests.protocol_fixtures import SYS_ID, channel_pair


def control_plane(tmp_path, *, uid='PRIVATE-UID', k_rev=None):
    k_rev = secrets.token_bytes(32) if k_rev is None else k_rev
    admin, kgc, ack, root = (new_private_key() for _ in range(4))
    metrics = RevocationOperationCounts()
    store = EmulatedPersistentRevocationStore(tmp_path/'revocation.sealed',
                secrets.token_bytes(32), SYS_ID)
    head_store = EmulatedPersistentCurrentHeadStore(tmp_path/'current-head.sealed',
                secrets.token_bytes(32),store.load())
    kgc_store = EmulatedPersistentKGCStateStore(tmp_path/'kgc-private.sealed',
                secrets.token_bytes(32),SYS_ID)
    engine = TEERevocationEngine(store,k_rev,public_key_bytes(kgc),ack,metrics=metrics)
    coordinator = LinearizedCurrentHeadCoordinator(store.load(),public_key_bytes(ack),
                                                    head_store,
                                                    metrics=metrics)
    manager = KGCRevocationManager(SYS_ID,k_rev,public_key_bytes(admin),kgc,
                                   public_key_bytes(ack),kgc_store,metrics=metrics)
    manager.register(uid)
    kgc_channel,tee_channel,*_ = channel_pair(root,EmulatedChallengeStore(),purpose='REV')
    return locals()


def update(plane,operation,*,uid='PRIVATE-UID',commit=True):
    manager=plane['manager']
    signature=sign_management_command(plane['admin'],SYS_ID,uid,operation,manager.version)
    delta=manager.rev(uid,operation,signature,plane['kgc_channel'])
    ack=plane['engine'].rev_state_upt(delta,plane['tee_channel'])
    if commit: manager.commit_ack(ack,plane['coordinator'])
    return delta,ack


def attach_real_coordinator(env,plane):
    env['enclave']=EmulatedAnonymousAuthorizationEnclave(
        coordinator=plane['coordinator'],clock=env['clock'],
        revocation_engine=plane['engine'])
    return env


def refresh_request(env,nonce=None,version_hint=0):
    from core.myabe08.credential import encode_private_ingress,sign_possession
    from core.myabe08.state import DURequestState
    from core.myabe08.tee import make_emulated_host_request
    if nonce is None: nonce=secrets.token_bytes(32)
    request=make_emulated_host_request(env['publication'],env['backend'],
        env['du_client'],1500,nonce=nonce,version_hint=version_hint)
    proof=sign_possession(env['auth'],SYS_ID,env['du_client'].binding,
        request.header_digest,request.request_nonce)
    env['request']=request
    env['du_request_state']=DURequestState.from_host_request(request)
    env['proof']=proof
    env['private_record']=env['du_client'].send(encode_private_ingress(
        env['credential'],env['blob'],proof))
    return env
