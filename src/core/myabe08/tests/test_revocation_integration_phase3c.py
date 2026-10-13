"""EMULATED access-time lifecycle with a real single-process coordinator."""
import hashlib

import pytest

from core.myabe08.crypto import BLS12381Backend
from core.myabe08.capability import authorization_bytes
from core.myabe08.errors import ProtocolRejectedError,StateSynchronizationError
from core.myabe08.publication import core_components_digest,filter_digest,header_digest
from core.myabe08.revocation import ACTIVATE,REVOKE
from core.myabe08.tee import EmulatedAnonymousAuthorizationEnclave
from core.myabe08.tests.protocol_fixtures import authorize,bootstrap,complete
from core.myabe08.tests.revocation_fixtures import (
    attach_real_coordinator,control_plane,refresh_request,update)


def test_revoke_activate_historical_pending_future_and_invariance(tmp_path,monkeypatch):
    x=bootstrap();p=control_plane(tmp_path,uid=x['credential'].uid)
    attach_real_coordinator(x,p)
    backend=x['backend'];ct=x['publication']
    def invariant():
        return (header_digest(ct.header,backend),filter_digest(ct.anonymous_filter),
                core_components_digest(ct.row_components,ct.occurrence_components,backend),
                x['tokens'],backend.serialize_scalar(x['recovery'].rk),
                x['context'].ctx_priv)
    frozen=invariant()
    original=BLS12381Backend.pair;calls={'n':0}
    def counted(self,g1,g2):
        calls['n']+=1
        return original(self,g1,g2)
    monkeypatch.setattr(BLS12381Backend,'pair',counted)
    auth_before=authorize(x)
    handle=p['manager']._registered[x['credential'].uid]
    host_visible=authorization_bytes(auth_before,backend)+repr(x['request']).encode()+repr(ct).encode()
    assert handle not in host_visible and x['credential'].uid.encode() not in host_visible
    assert x['metrics'].t0_pairings==1 and calls['n']==1
    message,tr,csp,recovered=complete(x,auth_before)
    assert message==x['plaintext'] and recovered==x['core'].e
    assert (len(tr.candidate_rows),len(tr.reconstruction_rows),len(tr.occurrence_slots))==(2,2,1)
    refresh_request(x)
    from core.myabe08.revocation import sign_management_command
    manager=p['manager']
    signature=sign_management_command(p['admin'],manager.sys_id,x['credential'].uid,
                                      REVOKE,manager.version)
    delta=manager.rev(x['credential'].uid,REVOKE,signature,p['kgc_channel'])
    assert manager.pending is not None and manager.version==p['coordinator'].version==0
    auth_pending=authorize(x)
    pending_env=dict(x)
    assert x['metrics'].t0_pairings==2
    ack=p['engine'].rev_state_upt(delta,p['tee_channel'])
    manager.commit_ack(ack,p['coordinator'])
    assert manager.version==p['coordinator'].version==p['store'].load().rev_version==1
    assert invariant()==frozen
    # Already issued Auth remains mathematically usable after the commit.
    assert complete(pending_env,auth_pending)[0]==x['plaintext']
    refresh_request(x)
    before=(x['metrics'].t0_pairings,x['metrics'].user_token_prf_count,
            x['metrics'].cap_signatures,calls['n'])
    with pytest.raises(ProtocolRejectedError,match='revoked'): authorize(x)
    assert (x['metrics'].t0_pairings,x['metrics'].user_token_prf_count,
            x['metrics'].cap_signatures,calls['n'])==before
    # A new ciphertext also carries no revocation component and is rejected.
    future=bootstrap();attach_real_coordinator(future,p)
    with pytest.raises(ProtocolRejectedError,match='revoked'): authorize(future)
    assert future['metrics'].t0_pairings==0
    assert invariant()==frozen
    update(p,ACTIVATE)
    refresh_request(x)
    restored=authorize(x)
    assert x['metrics'].t0_pairings==3
    assert complete(x,restored)[0]==x['plaintext']
    assert invariant()==frozen
    assert p['metrics'].revset_size==0 and p['metrics'].rev_version==2


def test_stale_local_and_unavailable_coordinator_before_t0(tmp_path,monkeypatch):
    x=bootstrap();p=control_plane(tmp_path,uid=x['credential'].uid)
    attach_real_coordinator(x,p)
    old=p['store'].path.read_bytes()
    update(p,REVOKE)
    p['store'].path.write_bytes(old)
    original=BLS12381Backend.pair;calls={'n':0}
    def counted(self,g1,g2):
        calls['n']+=1;return original(self,g1,g2)
    monkeypatch.setattr(BLS12381Backend,'pair',counted)
    with pytest.raises(StateSynchronizationError): authorize(x)
    assert calls['n']==x['metrics'].t0_pairings==0
    refresh_request(x)
    x['enclave']=EmulatedAnonymousAuthorizationEnclave(clock=x['clock'],
                                                       revocation_engine=p['engine'])
    with pytest.raises(StateSynchronizationError): authorize(x)
    assert calls['n']==x['metrics'].t0_pairings==0


def test_untrusted_version_hint_never_overrides_current_head(tmp_path):
    x=bootstrap();p=control_plane(tmp_path,uid=x['credential'].uid)
    attach_real_coordinator(x,p)
    update(p,REVOKE)
    x['du_server'].receive(x['private_record'])
    for hint in (0,1,100):
        refresh_request(x,version_hint=hint)
        with pytest.raises(ProtocolRejectedError,match='revoked'): authorize(x)
    assert x['metrics'].t0_pairings==0
    assert p['metrics'].revoked_rejections==3
