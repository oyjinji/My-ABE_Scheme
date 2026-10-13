"""Single-process coordinator schedules and stale-local detection."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from core.myabe08.errors import ProtocolRejectedError,StateSynchronizationError
from core.myabe08.revocation import (ACTIVATE,REVOKE,ExactRevocationSet,
    RevocationState,state_digest)
from core.myabe08.tests.protocol_fixtures import SYS_ID
from core.myabe08.tests.revocation_fixtures import control_plane,update


def _permit(plane,nonce=b'N'*32):
    return plane['coordinator'].authorization_transaction(sys_id=SYS_ID,fresh_nonce=nonce)


def test_fresh_permit_single_use_and_no_cached_head(tmp_path):
    p=control_plane(tmp_path)
    c=p['coordinator']
    with _permit(p) as txn:
        permit=txn.current_head()
        assert permit.active and permit.rev_version==0
        assert permit.state_digest==p['store'].load().state_digest
        assert len(permit.transaction_id)==len(permit.authenticated_record)==32
        p['engine'].check_active('PRIVATE-UID',permit)
        txn.commit_authorization(b'N'*32,b'D'*32)
        with pytest.raises(StateSynchronizationError): txn.commit_authorization(b'N'*32,b'D'*32)
    with pytest.raises(StateSynchronizationError): txn.current_head()
    with _permit(p,b'P'*32) as another:
        assert another.current_head().transaction_id!=permit.transaction_id
    assert c.authorization_commits==1
    assert p['metrics'].authorization_txn_begin==2
    assert p['metrics'].authorization_txn_commit==1
    assert p['metrics'].authorization_txn_abort==1


def test_pending_then_local_ahead_then_committed_revoked(tmp_path):
    p=control_plane(tmp_path)
    manager=p['manager'];admin=p['admin']
    from core.myabe08.revocation import sign_management_command
    signature=sign_management_command(admin,SYS_ID,'PRIVATE-UID',REVOKE,0)
    delta=manager.rev('PRIVATE-UID',REVOKE,signature,p['kgc_channel'])
    assert manager.pending is not None and manager.version==0
    with _permit(p) as txn:
        p['engine'].check_active('PRIVATE-UID',txn.current_head())
        txn.commit_authorization(b'N'*32,b'D'*32)
    ack=p['engine'].rev_state_upt(delta,p['tee_channel'])
    with _permit(p,b'B'*32) as txn:
        with pytest.raises(StateSynchronizationError):
            p['engine'].check_active('PRIVATE-UID',txn.current_head())
    manager.commit_ack(ack,p['coordinator'])
    with _permit(p,b'C'*32) as txn:
        with pytest.raises(ProtocolRejectedError,match='revoked'):
            p['engine'].check_active('PRIVATE-UID',txn.current_head())


def test_rollback_freeze_future_and_fork_all_fail_closed(tmp_path):
    p=control_plane(tmp_path)
    old_bytes=p['store'].path.read_bytes()
    update(p,REVOKE)
    v1_bytes=p['store'].path.read_bytes()
    update(p,ACTIVATE)
    v2=p['store'].load()
    assert p['coordinator'].version==2
    for stale in (old_bytes,v1_bytes):
        p['store'].path.write_bytes(stale)
        with _permit(p,b'S'*32) as txn:
            with pytest.raises(StateSynchronizationError):
                p['engine'].check_active('PRIVATE-UID',txn.current_head())
    p['store'].path.write_bytes(v1_bytes)
    # A frozen v1 and a rolled-back v1 are observationally identical here.
    # Restore an authenticated v2 snapshot using a fresh seal.
    p['store'].save(v2,expected_version=1)
    alternate=ExactRevocationSet((p['manager']._registered['PRIVATE-UID'],))
    fork=RevocationState(SYS_ID,2,alternate,state_digest(SYS_ID,2,alternate),v2.replay_acks)
    p['store'].save(fork,expected_version=2)
    with _permit(p,b'F'*32) as txn:
        with pytest.raises(StateSynchronizationError):
            p['engine'].check_active('PRIVATE-UID',txn.current_head())
    p['store'].save(v2,expected_version=2)
    ahead=RevocationState(SYS_ID,3,v2.revset,state_digest(SYS_ID,3,v2.revset),v2.replay_acks)
    p['store'].save(ahead,expected_version=2)
    with _permit(p,b'A'*32) as txn:
        with pytest.raises(StateSynchronizationError):
            p['engine'].check_active('PRIVATE-UID',txn.current_head())
    assert p['metrics'].stale_local_detections>=2


def test_authorization_commit_before_revoke_commit_linearizes_first(tmp_path):
    p=control_plane(tmp_path)
    delta,ack=update(p,REVOKE,commit=False)
    started=threading.Event();done=threading.Event()
    def commit_revoke():
        started.set()
        p['manager'].commit_ack(ack,p['coordinator'])
        done.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with _permit(p,b'Q'*32) as txn:
            permit=txn.current_head()
            future=pool.submit(commit_revoke)
            assert started.wait(2)
            assert not done.wait(.02)
            # The coordinator transaction linearizes this authorization first.
            txn.commit_authorization(b'Q'*32,b'D'*32)
        future.result(timeout=2)
    assert (p['coordinator'].authorization_commits,p['coordinator'].revocation_commits)==(1,1)
    assert permit.rev_version==0 and p['coordinator'].version==1


def test_revoke_commit_before_authorization_lookup_rejects(tmp_path):
    p=control_plane(tmp_path)
    update(p,REVOKE)
    with _permit(p) as txn:
        assert txn.current_head().rev_version==1
        with pytest.raises(ProtocolRejectedError,match='revoked'):
            p['engine'].check_active('PRIVATE-UID',txn.current_head())
    assert p['coordinator'].authorization_commits==0


def test_single_coordinator_concurrent_transactions_have_no_version_regression(tmp_path):
    p=control_plane(tmp_path)
    def one(index):
        nonce=index.to_bytes(32,'big')
        with _permit(p,nonce) as txn:
            permit=txn.current_head()
            p['engine'].check_active('PRIVATE-UID',permit)
            txn.commit_authorization(nonce,b'D'*32)
            return permit.rev_version
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(one,range(1,81)))==[0]*80
    update(p,REVOKE)
    assert p['coordinator'].version==1
    assert p['coordinator'].authorization_commits==80


def test_persistent_head_restart_and_file_rollback_detected(tmp_path):
    from core.myabe08.revocation import (EmulatedPersistentCurrentHeadStore,
                                         LinearizedCurrentHeadCoordinator)
    from core.myabe08.signing import public_key_bytes
    p=control_plane(tmp_path)
    old_head=p['head_store'].path.read_bytes()
    update(p,REVOKE)
    recovered_head=EmulatedPersistentCurrentHeadStore(p['head_store'].path,
        p['head_store']._key,p['store'].load())
    restarted=LinearizedCurrentHeadCoordinator(p['store'].load(),
        public_key_bytes(p['ack']),recovered_head)
    assert restarted.version==1 and restarted.digest==p['store'].load().state_digest
    p['head_store'].path.write_bytes(old_head)
    with pytest.raises(StateSynchronizationError):
        with _permit(p): pass
    with pytest.raises(StateSynchronizationError):
        LinearizedCurrentHeadCoordinator(p['store'].load(),
            public_key_bytes(p['ack']),recovered_head)


def test_head_file_change_during_authorization_aborts_commit(tmp_path):
    p=control_plane(tmp_path)
    old_head=p['head_store'].path.read_bytes()
    update(p,REVOKE)
    current_head=p['head_store'].path.read_bytes()
    with _permit(p,b'Z'*32) as txn:
        assert txn.current_head().rev_version==1
        p['head_store'].path.write_bytes(old_head)
        with pytest.raises(StateSynchronizationError,match='head changed'):
            txn.commit_authorization(b'Z'*32,b'D'*32)
    p['head_store'].path.write_bytes(current_head)
    assert p['coordinator'].authorization_commits==0


def test_concurrent_authorize_revoke_activate_has_no_revoked_head_success(tmp_path):
    p=control_plane(tmp_path)
    gate=threading.Barrier(2)
    def changes():
        gate.wait()
        update(p,REVOKE)
        update(p,ACTIVATE)
    def authorize_many():
        gate.wait()
        results=[]
        for number in range(1,101):
            nonce=number.to_bytes(32,'big')
            with _permit(p,nonce) as txn:
                permit=txn.current_head()
                try:
                    p['engine'].check_active('PRIVATE-UID',permit)
                    txn.commit_authorization(nonce,b'D'*32)
                    results.append(('success',permit.rev_version))
                except (ProtocolRejectedError,StateSynchronizationError):
                    results.append(('reject',permit.rev_version))
        return results
    with ThreadPoolExecutor(max_workers=2) as pool:
        update_future=pool.submit(changes)
        results=pool.submit(authorize_many).result(timeout=10)
        update_future.result(timeout=10)
    assert p['coordinator'].version==2
    assert all(version in (0,2) for outcome,version in results if outcome=='success')
    assert not any(outcome=='success' and version==1 for outcome,version in results)
    assert p['manager'].version==p['store'].load().rev_version==2
