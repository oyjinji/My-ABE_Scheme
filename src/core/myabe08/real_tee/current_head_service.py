"""KGC-side single-logical-head transaction core, not yet an SGX RPC adapter.

The caller must be a trusted KGC process with a pinned service signing key and
trusted time source. No CSP socket endpoint or attested channel is provided.
"""
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import secrets
import sqlite3
import threading

from ..encoding import UInt64, require_bytes, require_uint
from ..errors import ContractError, StateSynchronizationError
from ..revocation import RevocationState, verify_ack
from ..signing import public_key_bytes, sign_canonical, verify_canonical

PROFILE_ID='SINGLE_LOGICAL_KGC_CURRENT_HEAD_V1'


@dataclass(frozen=True)
class SignedHeadPermit:
    sys_id: bytes
    session_id: bytes
    request_nonce: bytes
    request_digest: bytes
    txn_id: bytes
    version: int
    state_digest: bytes
    service_time: int
    signature: bytes


def permit_fields(permit):
    if type(permit) is not SignedHeadPermit:
        raise ContractError('signed permit required')
    for name in ('session_id','request_nonce','request_digest','txn_id','state_digest'):
        require_bytes(getattr(permit,name),name,32)
    require_uint(permit.version,64,'head version')
    require_uint(permit.service_time,64,'service time')
    return (PROFILE_ID,permit.sys_id,permit.session_id,permit.request_nonce,
            permit.request_digest,permit.txn_id,UInt64(permit.version),
            permit.state_digest,UInt64(permit.service_time))


def verify_head_permit(permit,pinned_public):
    """Signature verification alone is not online freshness or transaction commit."""
    verify_canonical(pinned_public,permit.signature,'MYABE-KGC-HEAD-PERMIT',
                     *permit_fields(permit))
    return permit


class KGCCurrentHeadService:
    """SQLite-backed single-writer KGC authority for head transaction ordering.

    It has no network listener. Future SGX use requires RA-bound mutual channel
    and authenticated online calls; direct host/CSP calls are not trusted.
    """
    def __init__(self,path,sys_id,ack_public,service_private,*,trusted_time):
        require_bytes(sys_id,'SysID')
        require_bytes(ack_public,'TEE Ack public key',32)
        if trusted_time is None or not callable(trusted_time):
            raise StateSynchronizationError('authenticated time source required')
        self.path=Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self._lockfile=os.open(str(self.path)+'.lock',os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(self._lockfile,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except Exception:
            os.close(self._lockfile)
            raise StateSynchronizationError('single logical KGC head already open')
        self._lock=threading.RLock()
        self._db=sqlite3.connect(str(self.path),isolation_level=None,check_same_thread=False)
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('PRAGMA synchronous=FULL')
        self._db.execute('CREATE TABLE IF NOT EXISTS head ('
            'id INTEGER PRIMARY KEY CHECK(id=1), sys_id BLOB NOT NULL, '
            'version INTEGER NOT NULL, digest BLOB NOT NULL, service_time INTEGER NOT NULL)')
        self._db.execute('CREATE TABLE IF NOT EXISTS requests ('
            'nonce BLOB PRIMARY KEY, txn_id BLOB NOT NULL, status TEXT NOT NULL)')
        initial=RevocationState.initial(sys_id)
        self._db.execute('INSERT OR IGNORE INTO head VALUES (1,?,?,?,0)',
                         (sys_id,initial.rev_version,initial.state_digest))
        self.sys_id=sys_id
        self.ack_public=ack_public
        self.service_private=service_private
        self.service_public=public_key_bytes(service_private)
        self._trusted_time=trusted_time
        self._active=None
        self._head()  # Verify store binding at startup.

    def close(self):
        with self._lock:
            self._active=None
            self._db.close()
            fcntl.flock(self._lockfile,fcntl.LOCK_UN)
            os.close(self._lockfile)

    def _head(self):
        row=self._db.execute('SELECT sys_id,version,digest,service_time FROM head WHERE id=1').fetchone()
        if row is None or row[0]!=self.sys_id or len(row[2])!=32:
            raise StateSynchronizationError('KGC head storage binding mismatch')
        return row[1],row[2],row[3]

    def _now(self,last):
        value=self._trusted_time()
        if type(value) is not int or value<0 or value<last:
            raise StateSynchronizationError('trusted service time unavailable or regressed')
        return value

    def compare_local(self,version,digest):
        """Fail closed for stale/frozen, same-version fork, and local-ahead state."""
        require_uint(version,64,'local version')
        require_bytes(digest,'local state digest',32)
        with self._lock:
            head_version,head_digest,_=self._head()
            if version!=head_version or digest!=head_digest:
                raise StateSynchronizationError('local/head mismatch')
            return head_version,head_digest

    def begin_authorization(self,*,session_id,request_nonce,request_digest,
                            local_version,local_digest):
        for label,value in (('session ID',session_id),('request nonce',request_nonce),
                            ('request digest',request_digest)):
            require_bytes(value,label,32)
        with self._lock:
            if self._active is not None:
                raise StateSynchronizationError('KGC head transaction already active')
            self.compare_local(local_version,local_digest)
            version,digest,last=self._head()
            now=self._now(last)
            txn_id=secrets.token_bytes(32)
            try:
                self._db.execute('BEGIN IMMEDIATE')
                self._db.execute('INSERT INTO requests VALUES (?,?,?)',
                                 (request_nonce,txn_id,'pending'))
                self._db.execute('UPDATE head SET service_time=? WHERE id=1',(now,))
                self._db.execute('COMMIT')
            except sqlite3.IntegrityError:
                self._db.execute('ROLLBACK')
                raise StateSynchronizationError('request nonce replay')
            except Exception:
                self._db.execute('ROLLBACK')
                raise
            unsigned=SignedHeadPermit(self.sys_id,session_id,request_nonce,
                                      request_digest,txn_id,version,digest,now,b'')
            signature=sign_canonical(self.service_private,'MYABE-KGC-HEAD-PERMIT',
                                     *permit_fields(unsigned))
            permit=SignedHeadPermit(self.sys_id,session_id,request_nonce,
                                    request_digest,txn_id,version,digest,now,signature)
            self._active=permit
            return permit

    def commit_authorization(self,permit,bundle_digest):
        require_bytes(bundle_digest,'bundle digest',32)
        with self._lock:
            if self._active!=permit:
                raise StateSynchronizationError('authorization permit unavailable')
            verify_head_permit(permit,self.service_public)
            self.compare_local(permit.version,permit.state_digest)
            changed=self._db.execute('UPDATE requests SET status=? WHERE nonce=? AND txn_id=? AND status=?',
                                     ('committed',permit.request_nonce,permit.txn_id,'pending'))
            if changed.rowcount!=1:
                raise StateSynchronizationError('KGC request record missing')
            self._active=None

    def abort_authorization(self,permit):
        with self._lock:
            if self._active!=permit:
                raise StateSynchronizationError('authorization permit unavailable')
            changed=self._db.execute('UPDATE requests SET status=? WHERE nonce=? AND txn_id=? AND status=?',
                                     ('aborted',permit.request_nonce,permit.txn_id,'pending'))
            if changed.rowcount!=1:
                raise StateSynchronizationError('KGC request record missing')
            self._active=None

    def commit_revocation(self,old_version,old_digest,ack):
        with self._lock:
            if self._active is not None:
                raise StateSynchronizationError('authorization transaction active')
            verify_ack(ack,self.ack_public)
            version,digest,last=self._head()
            if (old_version!=version or old_digest!=digest or
                    ack.sys_id!=self.sys_id or ack.version!=version+1):
                raise StateSynchronizationError('KGC revocation head conflict')
            now=self._now(last)
            self._db.execute('BEGIN IMMEDIATE')
            try:
                self._db.execute('UPDATE head SET version=?,digest=?,service_time=? WHERE id=1',
                                 (ack.version,ack.new_state_digest,now))
                self._db.execute('COMMIT')
            except Exception:
                self._db.execute('ROLLBACK')
                raise
            return ack.version,ack.new_state_digest
