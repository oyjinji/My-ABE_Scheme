"""Exact RID/set/version/update correctness; no ABE pairing here."""
from dataclasses import replace
import hashlib
import hmac
import secrets

import pytest

from core.myabe08.encoding import encode
from core.myabe08.errors import (AuthenticationError,ContractError,
    ProtocolRejectedError,StateSynchronizationError)
from core.myabe08.revocation import (ACTIVATE,REVOKE,ExactRevocationSet,
    derive_revocation_handle,delta_plaintext,parse_delta,state_digest,
    sign_management_command,RevocationState,TEERevocationEngine)
from core.myabe08.signing import new_private_key,public_key_bytes
from core.myabe08.tests.protocol_fixtures import SYS_ID
from core.myabe08.tests.revocation_fixtures import control_plane,update


def test_rid_exact_derivation_and_independent_key_domain():
    key=b'R'*32
    uid='registered-A'
    expected=hmac.new(key,encode(('RID',SYS_ID,uid)),hashlib.sha256).digest()
    assert derive_revocation_handle(key,SYS_ID,uid)==expected
    assert len(expected)==32
    assert derive_revocation_handle(b'S'*32,SYS_ID,uid)!=expected
    assert derive_revocation_handle(key,b'OTHER-SYS',uid)!=expected
    assert derive_revocation_handle(key,SYS_ID,'registered-B')!=expected
    with pytest.raises(ContractError): derive_revocation_handle(b'bad',SYS_ID,uid)


def test_exact_set_canonical_digest_and_300_user_stress():
    handles=[derive_revocation_handle(b'R'*32,SYS_ID,'user-%03d'%i)
             for i in range(300)]
    current=ExactRevocationSet()
    assert not current.contains(handles[0])
    for handle in handles: current=current.with_operation(REVOKE,handle)
    assert current._size()==300
    assert all(current.contains(h) for h in handles)
    assert not current.contains(secrets.token_bytes(32))
    reordered=ExactRevocationSet(reversed(handles))
    assert state_digest(SYS_ID,300,current)==state_digest(SYS_ID,300,reordered)
    assert state_digest(SYS_ID,301,current)!=state_digest(SYS_ID,300,current)
    current=current.with_operation(ACTIVATE,handles[0])
    assert not current.contains(handles[0]) and all(current.contains(h) for h in handles[1:])
    with pytest.raises(ContractError): current.contains(b'bad')
    with pytest.raises(ProtocolRejectedError): current.with_operation(ACTIVATE,handles[0])
    with pytest.raises(ProtocolRejectedError): current.with_operation(REVOKE,handles[1])
    assert not hasattr(current,'dump_handles') and not hasattr(current,'list_revoked_users')


def test_fixed_width_delta_and_management_authentication(tmp_path):
    p=control_plane(tmp_path)
    m=p['manager']
    signature=sign_management_command(p['admin'],SYS_ID,'PRIVATE-UID',REVOKE,0)
    with pytest.raises(AuthenticationError):
        m.rev('PRIVATE-UID',REVOKE,b'Z'*64,p['kgc_channel'])
    with pytest.raises(ProtocolRejectedError):
        m.rev('not-registered',REVOKE,
              sign_management_command(p['admin'],SYS_ID,'not-registered',REVOKE,0),
              p['kgc_channel'])
    with pytest.raises(ContractError):
        sign_management_command(p['admin'],SYS_ID,'PRIVATE-UID',3,0)
    delta,ack=update(p,REVOKE)
    assert p['store'].load().rev_version==1 and p['coordinator'].version==1
    with pytest.raises(ProtocolRejectedError):
        m.rev('PRIVATE-UID',REVOKE,
              sign_management_command(p['admin'],SYS_ID,'PRIVATE-UID',REVOKE,1),p['kgc_channel'])
    activate,ack2=update(p,ACTIVATE)
    assert len(delta.protected_record)==len(activate.protected_record)
    assert b'PRIVATE-UID' not in delta.protected_record
    assert p['store'].load().rev_version==2 and p['store'].load().revset._size()==0
    assert p['metrics'].rev_operations==p['metrics'].activate_operations==1


def test_atomic_update_ack_replay_conflict_and_restart(tmp_path):
    p=control_plane(tmp_path)
    delta,ack=update(p,REVOKE,commit=False)
    assert p['manager'].status=='pending'
    state=p['store'].load()
    assert (state.rev_version,state.revset._size(),state.state_digest)==(1,1,ack.new_state_digest)
    assert p['manager'].version==p['coordinator'].version==0
    assert p['engine'].rev_state_upt(delta,p['tee_channel'])==ack
    assert p['store'].load().rev_version==1
    with pytest.raises(ProtocolRejectedError):
        p['manager'].rev('PRIVATE-UID',ACTIVATE,
            sign_management_command(p['admin'],SYS_ID,'PRIVATE-UID',ACTIVATE,0),p['kgc_channel'])
    bad=replace(ack,new_state_digest=b'X'*32)
    with pytest.raises(AuthenticationError): p['manager'].commit_ack(bad,p['coordinator'])
    assert p['manager'].status=='conflict'
    assert p['manager'].pending is not None and p['coordinator'].version==0
    p['manager'].commit_ack(ack,p['coordinator'])
    assert p['manager'].status=='committed'
    assert p['manager'].pending is None and p['coordinator'].version==1
    restarted=type(p['store'])(p['store'].path,p['store']._key,SYS_ID)
    recovered=restarted.load()
    assert recovered.rev_version==state.rev_version
    assert recovered.state_digest==state.state_digest
    assert recovered.revset.contains(p['manager']._registered['PRIVATE-UID'])
    assert p['metrics'].rev_state_updates==1


def test_delta_strict_version_predecessor_and_source(tmp_path):
    p=control_plane(tmp_path)
    handle=p['manager']._registered['PRIVATE-UID']
    initial=p['store'].load()
    for version,predecessor in ((2,initial.state_digest),(1,b'X'*32)):
        plain=delta_plaintext(SYS_ID,version,REVOKE,handle,predecessor)
        sig=p['kgc']
        from core.myabe08.signing import sign_canonical
        payload=encode(('MYABE-REV-SIGNED',plain,
                        sign_canonical(sig,'MYABE-REV-DELTA',plain)))
        from core.myabe08.revocation import record_wire
        from core.myabe08.types import RevocationUpdate
        protected=RevocationUpdate(record_wire(p['kgc_channel'].send(payload)))
        with pytest.raises(StateSynchronizationError):
            p['engine'].rev_state_upt(protected,p['tee_channel'])
        assert p['store'].load().rev_version==0
    plain=delta_plaintext(SYS_ID,1,REVOKE,handle,initial.state_digest)
    from core.myabe08.signing import sign_canonical
    from core.myabe08.revocation import record_wire
    from core.myabe08.types import RevocationUpdate
    forged=RevocationUpdate(record_wire(p['kgc_channel'].send(encode((
        'MYABE-REV-SIGNED',plain,sign_canonical(new_private_key(),'MYABE-REV-DELTA',plain))))))
    with pytest.raises(AuthenticationError): p['engine'].rev_state_upt(forged,p['tee_channel'])
    with pytest.raises(ContractError): parse_delta(delta_plaintext(SYS_ID,1,REVOKE,handle,initial.state_digest)[:-1])


def test_snapshot_tamper_wrong_key_and_local_digest_mismatch(tmp_path):
    p=control_plane(tmp_path)
    path=p['store'].path
    raw=path.read_bytes();path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
    with pytest.raises(AuthenticationError): p['store'].load()
    path.write_bytes(raw)
    from core.myabe08.revocation import EmulatedPersistentRevocationStore
    wrong=EmulatedPersistentRevocationStore(path,b'W'*32,SYS_ID)
    with pytest.raises(AuthenticationError): wrong.load()
    s=p['store'].load()
    with pytest.raises(StateSynchronizationError):
        replace(s,state_digest=b'X'*32).validate()


def test_conflicting_same_version_old_update_and_protected_tamper(tmp_path):
    from core.myabe08.revocation import record_wire
    from core.myabe08.signing import sign_canonical
    from core.myabe08.types import RevocationUpdate
    p=control_plane(tmp_path)
    delta,ack=update(p,REVOKE)
    handle=p['manager']._registered['PRIVATE-UID']
    assert p['engine'].rev_state_upt(delta,p['tee_channel'])==ack
    conflicting_plain=delta_plaintext(SYS_ID,1,ACTIVATE,handle,
                                       RevocationState.initial(SYS_ID).state_digest)
    conflict=RevocationUpdate(record_wire(p['kgc_channel'].send(encode((
        'MYABE-REV-SIGNED',conflicting_plain,
        sign_canonical(p['kgc'],'MYABE-REV-DELTA',conflicting_plain))))))
    with pytest.raises(StateSynchronizationError):
        p['engine'].rev_state_upt(conflict,p['tee_channel'])
    assert p['store'].load().rev_version==1
    new_plain=delta_plaintext(SYS_ID,2,ACTIVATE,handle,p['store'].load().state_digest)
    valid=RevocationUpdate(record_wire(p['kgc_channel'].send(encode((
        'MYABE-REV-SIGNED',new_plain,
        sign_canonical(p['kgc'],'MYABE-REV-DELTA',new_plain))))))
    raw=bytearray(valid.protected_record);raw[-1]^=1
    with pytest.raises((AuthenticationError,ContractError)):
        p['engine'].rev_state_upt(RevocationUpdate(bytes(raw)),p['tee_channel'])
    # Failed AEAD verification does not advance the channel sequence or state.
    assert p['store'].load().rev_version==1
    assert p['engine'].rev_state_upt(valid,p['tee_channel']).version==2


def test_update_and_ack_host_privacy_and_key_separation(tmp_path):
    p=control_plane(tmp_path,k_rev=b'R'*32)
    delta,ack=update(p,REVOKE)
    handle=derive_revocation_handle(b'R'*32,SYS_ID,'PRIVATE-UID')
    public=delta.protected_record+ack.signature+repr(ack).encode()+repr(p['metrics']).encode()
    assert b'PRIVATE-UID' not in public and handle not in public
    assert b'PRIVATE-UID' not in p['store'].path.read_bytes()
    assert handle not in p['store'].path.read_bytes()
    assert p['metrics'].n_registered==1
    assert p['metrics'].revset_size==1
    assert p['metrics'].delta_bytes==len(delta.protected_record)
    assert p['metrics'].state_snapshot_bytes==len(p['store'].path.read_bytes())
    assert p['manager']._k_rev!=p['store']._key
    assert p['manager']._k_rev!=p['kgc_channel']._send_key
    assert b'PRIVATE-UID' not in p['kgc_store'].path.read_bytes()


def test_kgc_pending_restart_and_head_commit_crash_recovery(tmp_path):
    from core.myabe08.revocation import KGCRevocationManager
    p=control_plane(tmp_path)
    delta,ack=update(p,REVOKE,commit=False)
    original=p['manager']
    def restart():
        return KGCRevocationManager(SYS_ID,p['k_rev'],public_key_bytes(p['admin']),
            p['kgc'],public_key_bytes(p['ack']),p['kgc_store'])
    recovered=restart()
    assert recovered.status=='pending' and recovered.pending==original.pending
    assert recovered.registered_count()==1
    with pytest.raises(AuthenticationError):
        KGCRevocationManager(SYS_ID,b'W'*32,public_key_bytes(p['admin']),
            p['kgc'],public_key_bytes(p['ack']),p['kgc_store'])
    # Simulate a crash after coordinator head persist, before KGC snapshot commit.
    p['coordinator'].commit_revocation(recovered.version,recovered.digest,ack)
    assert p['coordinator'].version==1 and p['kgc_store'].load()[0]==0
    after_crash=restart()
    after_crash.commit_ack(ack,p['coordinator'])
    assert after_crash.version==p['coordinator'].version==1
    assert after_crash.status=='committed' and after_crash.pending is None
    assert p['kgc_store'].load()[0]==1
    assert p['coordinator'].revocation_commits==1


def test_two_kgc_managers_cannot_publish_conflicting_same_version(tmp_path):
    from core.myabe08.revocation import KGCRevocationManager,EmulatedPersistentKGCStateStore
    p=control_plane(tmp_path)
    second_store=EmulatedPersistentKGCStateStore(p['kgc_store'].path,
        p['kgc_store']._key,SYS_ID)
    stale=KGCRevocationManager(SYS_ID,p['k_rev'],public_key_bytes(p['admin']),
        p['kgc'],public_key_bytes(p['ack']),second_store)
    signature=sign_management_command(p['admin'],SYS_ID,'PRIVATE-UID',REVOKE,0)
    first=p['manager'].rev('PRIVATE-UID',REVOKE,signature,p['kgc_channel'])
    with pytest.raises(StateSynchronizationError):
        stale.rev('PRIVATE-UID',REVOKE,signature,p['kgc_channel'])
    assert p['kgc_store'].load()[4]==p['manager'].pending
    assert p['kgc_store'].load()[4].protected==first


def test_version_five_restart_recovers_exact_state_and_digest(tmp_path):
    from core.myabe08.revocation import (EmulatedPersistentRevocationStore,
        EmulatedPersistentCurrentHeadStore,EmulatedPersistentKGCStateStore,
        KGCRevocationManager,LinearizedCurrentHeadCoordinator)
    p=control_plane(tmp_path)
    for operation in (REVOKE,ACTIVATE,REVOKE,ACTIVATE,REVOKE):
        update(p,operation)
    original=p['store'].load()
    assert original.rev_version==5 and original.revset._size()==1
    tee_restarted=EmulatedPersistentRevocationStore(p['store'].path,p['store']._key,SYS_ID)
    head_restarted=EmulatedPersistentCurrentHeadStore(p['head_store'].path,
        p['head_store']._key,tee_restarted.load())
    kgc_restarted=EmulatedPersistentKGCStateStore(p['kgc_store'].path,
        p['kgc_store']._key,SYS_ID)
    manager=KGCRevocationManager(SYS_ID,p['k_rev'],public_key_bytes(p['admin']),
        p['kgc'],public_key_bytes(p['ack']),kgc_restarted)
    coordinator=LinearizedCurrentHeadCoordinator(tee_restarted.load(),
        public_key_bytes(p['ack']),head_restarted)
    recovered=tee_restarted.load()
    assert recovered.rev_version==original.rev_version==manager.version==coordinator.version==5
    assert recovered.state_digest==original.state_digest==manager.digest==coordinator.digest
    assert recovered.revset._canonical()==original.revset._canonical()


def test_v3_missing_v2_is_rejected_without_state_jump(tmp_path):
    from core.myabe08.revocation import record_wire
    from core.myabe08.signing import sign_canonical
    from core.myabe08.types import RevocationUpdate
    p=control_plane(tmp_path)
    update(p,REVOKE)
    handle=p['manager']._registered['PRIVATE-UID']
    current=p['store'].load()
    plain=delta_plaintext(SYS_ID,3,ACTIVATE,handle,current.state_digest)
    signed=encode(('MYABE-REV-SIGNED',plain,
                   sign_canonical(p['kgc'],'MYABE-REV-DELTA',plain)))
    protected=RevocationUpdate(record_wire(p['kgc_channel'].send(signed)))
    with pytest.raises(StateSynchronizationError):
        p['engine'].rev_state_upt(protected,p['tee_channel'])
    assert p['store'].load().rev_version==p['coordinator'].version==1
