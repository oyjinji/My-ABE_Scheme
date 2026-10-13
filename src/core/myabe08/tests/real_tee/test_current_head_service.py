"""KGC-side transaction core tests; no remote SGX integration claim."""
from dataclasses import replace

import pytest

from core.myabe08.errors import AuthenticationError, StateSynchronizationError
from core.myabe08.real_tee.current_head_service import (
    KGCCurrentHeadService, verify_head_permit)
from core.myabe08.revocation import RevocationState, sign_ack
from core.myabe08.signing import new_private_key, public_key_bytes

SYS=b'HEAD-TEST-SYS'


def test_kcg_head_ordering_persistence_and_conflicts(tmp_path):
    ack_key=new_private_key()
    service_key=new_private_key()
    now=[1000]
    path=tmp_path/'kgc-head.sqlite'
    initial=RevocationState.initial(SYS)
    svc=KGCCurrentHeadService(path,SYS,public_key_bytes(ack_key),service_key,
                              trusted_time=lambda: now[0])
    try:
        with pytest.raises(StateSynchronizationError):
            KGCCurrentHeadService(path,SYS,public_key_bytes(ack_key),service_key,
                                  trusted_time=lambda: now[0])
        permit=svc.begin_authorization(session_id=b'S'*32,request_nonce=b'N'*32,
            request_digest=b'R'*32,local_version=0,
            local_digest=initial.state_digest)
        verify_head_permit(permit,svc.service_public)
        with pytest.raises(AuthenticationError):
            verify_head_permit(replace(permit,signature=b'X'*64),svc.service_public)
        ack=sign_ack(ack_key,SYS,1,b'U'*32,b'H'*32)
        with pytest.raises(StateSynchronizationError):
            svc.commit_revocation(0,initial.state_digest,ack)
        svc.commit_authorization(permit,b'B'*32)
        with pytest.raises(StateSynchronizationError):
            svc.commit_authorization(permit,b'B'*32)
        with pytest.raises(StateSynchronizationError):
            svc.begin_authorization(session_id=b'S'*32,request_nonce=b'N'*32,
                request_digest=b'R'*32,local_version=0,
                local_digest=initial.state_digest)
        assert svc.commit_revocation(0,initial.state_digest,ack)==(1,b'H'*32)
        for version,digest in ((0,initial.state_digest),(1,b'F'*32),(2,b'H'*32)):
            with pytest.raises(StateSynchronizationError):
                svc.compare_local(version,digest)
        assert svc.compare_local(1,b'H'*32)==(1,b'H'*32)
    finally:
        svc.close()
    restored=KGCCurrentHeadService(path,SYS,public_key_bytes(ack_key),service_key,
                                   trusted_time=lambda: now[0])
    try:
        assert restored.compare_local(1,b'H'*32)==(1,b'H'*32)
        now[0]=999
        with pytest.raises(StateSynchronizationError):
            restored.begin_authorization(session_id=b'S'*32,request_nonce=b'Q'*32,
                request_digest=b'R'*32,local_version=1,local_digest=b'H'*32)
    finally:
        restored.close()


def test_time_source_required(tmp_path):
    with pytest.raises(StateSynchronizationError):
        KGCCurrentHeadService(tmp_path/'head.sqlite',SYS,b'A'*32,
                              new_private_key(),trusted_time=None)
