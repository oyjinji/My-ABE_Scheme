"""Read-only TEST-only deterministic revocation profile regression vectors."""
import hashlib
import json
from pathlib import Path

from core.myabe08.attestation import EmulatedChallengeStore,issue_emulated_evidence
from core.myabe08.channel import (establish_emulated_channel,x25519_private_from_seed,
                                  x25519_public_bytes)
from core.myabe08.revocation import (REVOKE,ACTIVATE,EmulatedPersistentRevocationStore,
    EmulatedPersistentCurrentHeadStore,EmulatedPersistentKGCStateStore,
    TEERevocationEngine,KGCRevocationManager,
    LinearizedCurrentHeadCoordinator,
    derive_revocation_handle,delta_plaintext,ack_wire,encode_current_head_permit,
    sign_management_command)
from core.myabe08.signing import private_key_from_seed,public_key_bytes
from core.myabe08.tests.protocol_fixtures import SYS_ID,MEASUREMENT

VECTOR=Path(__file__).parent/'vectors'/'profile_v1.json'
PRIOR_SHA256='545e5d1b5e8d4714d52cb9822ad2543815fdda3e44640f7e219a66be09ce54f2'


def test_phase1_through_3b_vectors_unchanged():
    data=json.loads(VECTOR.read_text())
    previous={k:v for k,v in data.items() if k!='phase3c'}
    canonical=json.dumps(previous,sort_keys=True,separators=(',',':')).encode()
    assert hashlib.sha256(canonical).hexdigest()==PRIOR_SHA256


def test_fixed_revocation_bytes_and_permit(tmp_path):
    v=json.loads(VECTOR.read_text())['phase3c']
    assert 'NOT PRODUCTION SECRET' in v['notice']
    key={name:bytes.fromhex(raw) for name,raw in v['test_keys_hex'].items()}
    kgc,admin,ack_key,root=(private_key_from_seed(key[name]) for name in
                            ('kgc_seed','admin_seed','ack_seed','root_seed'))
    client=x25519_private_from_seed(key['client_x25519_seed'])
    server=x25519_private_from_seed(key['server_x25519_seed'])
    evidence=issue_emulated_evidence(root,SYS_ID,MEASUREMENT,3,b'C'*32,
                                     x25519_public_bytes(server),b'S'*32)
    count=[0]
    def channel_nonce(n):
        count[0]+=1
        return bytes([count[0]])*n
    client_channel,server_channel=establish_emulated_channel(client,server,evidence,
        public_key_bytes(root),SYS_ID,MEASUREMENT,2,b'C'*32,EmulatedChallengeStore(),
        purpose='REV',nonce_source=channel_nonce)
    snap_count=[0]
    def snapshot_nonce(n):
        snap_count[0]+=1
        return bytes([snap_count[0]+80])*n
    store=EmulatedPersistentRevocationStore(tmp_path/'vector.sealed',
        key['snapshot_key'],SYS_ID,nonce_source=snapshot_nonce)
    head_store=EmulatedPersistentCurrentHeadStore(tmp_path/'vector-head.sealed',
        b'H'*32,store.load(),nonce_source=lambda n:b'J'*n)
    kgc_store=EmulatedPersistentKGCStateStore(tmp_path/'vector-kgc.sealed',
        b'K'*32,SYS_ID,nonce_source=lambda n:b'L'*n)
    engine=TEERevocationEngine(store,key['k_rev'],public_key_bytes(kgc),ack_key)
    coord=LinearizedCurrentHeadCoordinator(store.load(),public_key_bytes(ack_key),head_store,
        nonce_source=lambda n:b'X'*n,permit_key=key['permit_key'])
    manager=KGCRevocationManager(SYS_ID,key['k_rev'],public_key_bytes(admin),kgc,
                                 public_key_bytes(ack_key),kgc_store)
    manager.register(v['uid'])
    handle=derive_revocation_handle(key['k_rev'],SYS_ID,v['uid'])
    assert handle.hex()==v['rh_id_hex']
    assert store.load().state_digest.hex()==v['state_v0_digest_hex']
    for op,prefix,version,predecessor in (
        (REVOKE,'revoke',0,'state_v0_digest_hex'),
        (ACTIVATE,'activate',1,'state_v1_digest_hex')):
        signature=sign_management_command(admin,SYS_ID,v['uid'],op,version)
        protected=manager.rev(v['uid'],op,signature,client_channel)
        plain=delta_plaintext(SYS_ID,version+1,op,handle,
                              bytes.fromhex(v[predecessor]))
        assert plain.hex()==v[prefix+'_delta_plain_hex']
        assert protected.protected_record.hex()==v[prefix+'_protected_record_hex']
        ack=engine.rev_state_upt(protected,server_channel)
        assert ack_wire(ack).hex()==v['ack_v'+str(version+1)+'_hex']
        manager.commit_ack(ack,coord)
        assert store.load().state_digest.hex()==v['state_v'+str(version+1)+'_digest_hex']
    with coord.authorization_transaction(sys_id=SYS_ID,fresh_nonce=b'Q'*32) as txn:
        permit=txn.current_head()
        coord.verify_permit(permit)
        assert encode_current_head_permit(permit).hex()==v['current_head_permit_hex']
        txn.commit_authorization(b'Q'*32,b'D'*32)
