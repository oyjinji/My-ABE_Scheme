"""MYABE-08 exact revocation state for one software logical coordinator.

No hardware isolation, durable anti-rollback, or distributed consensus claim.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import threading

from .channel import EmulatedChannelEndpoint, EmulatedChannelRecord
from .crypto import AES256GCMSIV
from .encoding import UInt32, UInt64, decode, encode, require_bytes, require_uint
from .errors import AuthenticationError, ContractError, ProtocolRejectedError, StateSynchronizationError
from .signing import sign_canonical, verify_canonical
from .state import CurrentHeadPermit
from .types import RevocationUpdate

SNAPSHOT_SCHEMA = 'MYABE08-REV-SNAPSHOT-V1'
HEAD_SCHEMA = 'MYABE08-CURRENT-HEAD-V1'
KGC_SCHEMA = 'MYABE08-KGC-REV-V1'
COORDINATOR_PROFILE = 'EMULATED_SINGLE_LOGICAL_COORDINATOR_V1'
REVOKE = 1
ACTIVATE = 2
_PATH_LOCKS = {}
_PATH_LOCKS_GUARD = threading.Lock()


def _path_lock(path):
    """Share a lock across same-process store instances for one canonical path."""
    name = str(Path(path).resolve())
    with _PATH_LOCKS_GUARD:
        if name not in _PATH_LOCKS: _PATH_LOCKS[name] = threading.RLock()
        return _PATH_LOCKS[name]


def derive_revocation_handle(k_rev, sys_id, uid):
    """RID HMAC key is independent of token/transport/capability keys."""
    require_bytes(k_rev, 'K_rev', 32)
    require_bytes(sys_id, 'SysID')
    if type(uid) is not str or not uid:
        raise ContractError('registered UID required')
    return hmac.new(k_rev, encode(('RID', sys_id, uid)), hashlib.sha256).digest()


class ExactRevocationSet:
    """Private exact 32-byte membership; no host enumeration interface."""
    def __init__(self, handles=()):
        self._handles = frozenset(_handle(x) for x in handles)

    def contains(self, handle):
        return _handle(handle) in self._handles

    def with_operation(self, operation, handle):
        handle = _handle(handle)
        if operation == REVOKE:
            if handle in self._handles: raise ProtocolRejectedError('redundant revoke')
            return ExactRevocationSet(self._handles | {handle})
        if operation == ACTIVATE:
            if handle not in self._handles: raise ProtocolRejectedError('redundant activate')
            return ExactRevocationSet(self._handles - {handle})
        raise ContractError('unknown revocation operation')

    def _canonical(self):
        return tuple(sorted(self._handles))

    def _size(self):
        return len(self._handles)


def _handle(value):
    require_bytes(value, 'rh_id', 32)
    return value


def state_digest(sys_id, version, handles):
    require_bytes(sys_id, 'SysID')
    require_uint(version, 64, 'rev_version')
    if type(handles) is not ExactRevocationSet:
        raise ContractError('ExactRevocationSet required')
    return hashlib.sha256(encode(('MYABE-REV-STATE', sys_id, UInt64(version),
                                  handles._canonical()))).digest()


@dataclass(frozen=True)
class RevocationState:
    sys_id: bytes
    rev_version: int
    revset: ExactRevocationSet = field(repr=False)
    state_digest: bytes
    replay_acks: tuple = field(default=(), repr=False)

    @classmethod
    def initial(cls, sys_id):
        empty = ExactRevocationSet()
        return cls(sys_id, 0, empty, state_digest(sys_id, 0, empty))

    def validate(self):
        if self.state_digest != state_digest(self.sys_id, self.rev_version, self.revset):
            raise StateSynchronizationError('local state digest mismatch')
        for update_hash, ack_wire in self.replay_acks:
            require_bytes(update_hash, 'replay update digest', 32)
            parse_ack(ack_wire)
        return self


def delta_plaintext(sys_id, version, operation, handle, previous_digest):
    require_bytes(sys_id, 'SysID')
    require_uint(version, 64, 'update version')
    if version == 0 or operation not in (REVOKE, ACTIVATE) or type(operation) is not int:
        raise ContractError('invalid revocation operation/version')
    _handle(handle)
    require_bytes(previous_digest, 'previous state digest', 32)
    return encode(('MYABE-REV-DELTA', sys_id, UInt64(version), UInt32(operation),
                   handle, previous_digest))


def parse_delta(raw):
    obj = decode(raw)
    if (type(obj) is not tuple or len(obj) != 6 or obj[0] != 'MYABE-REV-DELTA'
            or type(obj[2]) is not UInt64 or type(obj[3]) is not UInt32):
        raise ContractError('revocation delta schema mismatch')
    _, sys_id, version, operation, handle, predecessor = obj
    if delta_plaintext(sys_id, version.value, operation.value, handle, predecessor) != raw:
        raise ContractError('noncanonical revocation delta')
    return sys_id, version.value, operation.value, handle, predecessor


def management_fields(sys_id, uid, operation, expected_version):
    require_bytes(sys_id, 'SysID')
    if type(uid) is not str or not uid: raise ContractError('UID required')
    if type(operation) is not int or operation not in (REVOKE, ACTIVATE):
        raise ContractError('unknown management operation')
    require_uint(expected_version, 64, 'expected version')
    return sys_id, uid, UInt32(operation), UInt64(expected_version)


def sign_management_command(admin_private, sys_id, uid, operation, expected_version):
    return sign_canonical(admin_private, 'MYABE-REV-MGMT',
                          *management_fields(sys_id, uid, operation, expected_version))


def record_wire(record):
    if type(record) is not EmulatedChannelRecord:
        raise ContractError('protected channel record required')
    return encode(('MYABE-REV-RECORD', record.session_id, record.direction,
                   UInt64(record.sequence), record.nonce, record.ciphertext))


def parse_record(raw):
    obj = decode(raw)
    if (type(obj) is not tuple or len(obj) != 6 or obj[0] != 'MYABE-REV-RECORD'
            or type(obj[3]) is not UInt64):
        raise ContractError('protected record schema mismatch')
    record = EmulatedChannelRecord(obj[1], obj[2], obj[3].value, obj[4], obj[5])
    if record_wire(record) != raw: raise ContractError('noncanonical protected record')
    return record


@dataclass(frozen=True)
class RevocationAckV1:
    sys_id: bytes
    version: int
    update_digest: bytes
    new_state_digest: bytes
    signature: bytes = field(repr=False)


def ack_fields(ack):
    require_bytes(ack.sys_id, 'SysID')
    require_uint(ack.version, 64, 'Ack version')
    require_bytes(ack.update_digest, 'update digest', 32)
    require_bytes(ack.new_state_digest, 'new state digest', 32)
    return ack.sys_id, UInt64(ack.version), ack.update_digest, ack.new_state_digest


def ack_wire(ack):
    return encode(('MYABE-REV-ACK',) + ack_fields(ack) + (ack.signature,))


def parse_ack(raw):
    obj = decode(raw)
    if (type(obj) is not tuple or len(obj) != 6 or obj[0] != 'MYABE-REV-ACK'
            or type(obj[2]) is not UInt64):
        raise ContractError('Ack schema mismatch')
    ack = RevocationAckV1(obj[1], obj[2].value, obj[3], obj[4], obj[5])
    if ack_wire(ack) != raw: raise ContractError('noncanonical Ack')
    return ack


def sign_ack(private, sys_id, version, update_digest, new_digest):
    unsigned = RevocationAckV1(sys_id, version, update_digest, new_digest, b'')
    signature = sign_canonical(private, 'MYABE-REV-ACK', *ack_fields(unsigned))
    return RevocationAckV1(sys_id, version, update_digest, new_digest, signature)


def verify_ack(ack, public):
    verify_canonical(public, ack.signature, 'MYABE-REV-ACK', *ack_fields(ack))
    return ack


def encode_current_head_permit(permit):
    if type(permit) is not CurrentHeadPermit:
        raise ContractError('CurrentHeadPermit required')
    require_uint(permit.rev_version,64,'head version')
    for label,value in (('state digest',permit.state_digest),
                        ('transaction ID',permit.transaction_id),
                        ('authenticated record',permit.authenticated_record)):
        require_bytes(value,label,32)
    return encode(('MYABE-CURRENT-HEAD-PERMIT',permit.sys_id,permit.fresh_nonce,
                   UInt64(permit.rev_version),permit.state_digest,
                   permit.transaction_id,permit.authenticated_record,
                   UInt32(1 if permit.active else 0)))


class EmulatedPersistentRevocationStore:
    """Atomic sealed local snapshot; OS rollback remains possible."""
    def __init__(self, path, key, sys_id, *, nonce_source=None):
        require_bytes(key, 'independent snapshot key', 32)
        require_bytes(sys_id, 'SysID')
        self.path = Path(path)
        self._key = key
        self.sys_id = sys_id
        self._nonce_source = secrets.token_bytes if nonce_source is None else nonce_source
        self._lock = _path_lock(self.path)
        if not self.path.exists(): self.save(RevocationState.initial(sys_id), expected_version=None)

    def _ad(self):
        return encode(('MYABE-REV-SNAPSHOT', self.sys_id, SNAPSHOT_SCHEMA))

    def _encode_state(self, state):
        state.validate()
        if state.sys_id != self.sys_id: raise ContractError('snapshot SysID mismatch')
        return encode((SNAPSHOT_SCHEMA, state.sys_id, UInt64(state.rev_version),
                       state.revset._canonical(), state.state_digest, state.replay_acks))

    def load(self):
        with self._lock:
            raw = self.path.read_bytes()
            if len(raw) <= 28: raise AuthenticationError('sealed snapshot truncated')
            nonce, ciphertext = raw[:12], raw[12:]
            plain = AES256GCMSIV().decrypt(self._key, nonce, ciphertext, self._ad())
            obj = decode(plain)
            if (type(obj) is not tuple or len(obj) != 6 or obj[0] != SNAPSHOT_SCHEMA
                    or type(obj[2]) is not UInt64 or type(obj[3]) is not tuple
                    or type(obj[5]) is not tuple):
                raise ContractError('snapshot schema mismatch')
            state = RevocationState(obj[1], obj[2].value, ExactRevocationSet(obj[3]),
                                    obj[4], obj[5]).validate()
            if obj[3] != state.revset._canonical() or self._encode_state(state) != plain:
                raise ContractError('noncanonical snapshot')
            return state

    def save(self, state, *, expected_version):
        with self._lock:
            if expected_version is not None and self.load().rev_version != expected_version:
                raise StateSynchronizationError('snapshot version changed')
            plain = self._encode_state(state)
            nonce = self._nonce_source(12)
            require_bytes(nonce, 'snapshot nonce', 12)
            sealed = nonce + AES256GCMSIV().encrypt(self._key, nonce, plain, self._ad())
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.path.with_name(self.path.name + '.' + secrets.token_hex(12) + '.tmp')
            try:
                with open(temp, 'xb') as out:
                    out.write(sealed)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(str(temp), str(self.path))
                fd = os.open(str(self.path.parent), os.O_RDONLY)
                try: os.fsync(fd)
                finally: os.close(fd)
            finally:
                if temp.exists(): temp.unlink()
            return len(sealed)


class EmulatedPersistentCurrentHeadStore:
    """Independent authenticated head file; no OS-level anti-rollback claim."""
    def __init__(self, path, key, initial_state, *, nonce_source=None):
        initial_state.validate()
        require_bytes(key, 'independent head key', 32)
        self.path = Path(path)
        self.sys_id = initial_state.sys_id
        self._key = key
        self._nonce_source = secrets.token_bytes if nonce_source is None else nonce_source
        self._lock = _path_lock(self.path)
        if not self.path.exists():
            self.save(initial_state.rev_version,initial_state.state_digest,
                      expected_version=None,expected_digest=None,
                      predecessor_digest=b'\x00'*32,update_digest=b'\x00'*32)

    def _ad(self):
        return encode(('MYABE-HEAD-SEAL',self.sys_id,HEAD_SCHEMA))

    def load(self):
        with self._lock:
            raw=self.path.read_bytes()
            if len(raw)<=28: raise AuthenticationError('sealed head truncated')
            plain=AES256GCMSIV().decrypt(self._key,raw[:12],raw[12:],self._ad())
            obj=decode(plain)
            if (type(obj) is not tuple or len(obj)!=6 or obj[0]!=HEAD_SCHEMA or
                    obj[1]!=self.sys_id or type(obj[2]) is not UInt64):
                raise ContractError('head schema mismatch')
            require_bytes(obj[3],'head digest',32)
            require_bytes(obj[4],'head predecessor digest',32)
            require_bytes(obj[5],'head update digest',32)
            if encode(obj)!=plain: raise ContractError('noncanonical head')
            return obj[2].value,obj[3]

    def transition(self):
        with self._lock:
            raw=self.path.read_bytes()
            plain=AES256GCMSIV().decrypt(self._key,raw[:12],raw[12:],self._ad())
            obj=decode(plain)
            self.load()
            return obj[4],obj[5]

    def save(self,version,digest,*,expected_version,expected_digest,
             predecessor_digest,update_digest):
        with self._lock:
            require_uint(version,64,'head version')
            require_bytes(digest,'head digest',32)
            require_bytes(predecessor_digest,'head predecessor digest',32)
            require_bytes(update_digest,'head update digest',32)
            if expected_version is not None and self.load()!=(expected_version,expected_digest):
                raise StateSynchronizationError('persistent head changed')
            nonce=self._nonce_source(12)
            require_bytes(nonce,'head nonce',12)
            plain=encode((HEAD_SCHEMA,self.sys_id,UInt64(version),digest,
                          predecessor_digest,update_digest))
            sealed=nonce+AES256GCMSIV().encrypt(self._key,nonce,plain,self._ad())
            self.path.parent.mkdir(parents=True,exist_ok=True)
            temp=self.path.with_name(self.path.name+'.'+secrets.token_hex(12)+'.tmp')
            try:
                with open(temp,'xb') as out:
                    out.write(sealed);out.flush();os.fsync(out.fileno())
                os.replace(str(temp),str(self.path))
                fd=os.open(str(self.path.parent),os.O_RDONLY)
                try: os.fsync(fd)
                finally: os.close(fd)
            finally:
                if temp.exists(): temp.unlink()
            return len(sealed)


@dataclass(frozen=True)
class PendingUpdateV1:
    version: int
    operation: int
    handle: bytes = field(repr=False)
    previous_digest: bytes
    protected: RevocationUpdate = field(repr=False)
    update_digest: bytes
    expected_digest: bytes


class EmulatedPersistentKGCStateStore:
    """Private authenticated KGC registry/pending file; distinct from TEE state."""
    def __init__(self,path,key,sys_id,*,nonce_source=None):
        require_bytes(key,'independent KGC state key',32)
        require_bytes(sys_id,'SysID')
        self.path=Path(path)
        self.sys_id=sys_id
        self._key=key
        self._nonce_source=secrets.token_bytes if nonce_source is None else nonce_source
        self._lock=_path_lock(self.path)
        if not self.path.exists():
            empty=ExactRevocationSet()
            self.save(0,state_digest(sys_id,0,empty),{},empty,None,'committed',
                      expected_version=None,expected_generation=None)

    def _ad(self):
        return encode(('MYABE-KGC-REV-SEAL',self.sys_id,KGC_SCHEMA))

    def _plain(self,version,digest,registered,handles,pending,status,generation):
        require_uint(version,64,'KGC version')
        require_uint(generation,64,'KGC snapshot generation')
        require_bytes(digest,'KGC digest',32)
        if type(registered) is not dict or type(handles) is not ExactRevocationSet:
            raise ContractError('KGC state shape mismatch')
        if digest!=state_digest(self.sys_id,version,handles):
            raise StateSynchronizationError('KGC state digest mismatch')
        entries=tuple((uid,_handle(handle)) for uid,handle in sorted(registered.items()))
        for uid,_ in entries:
            if type(uid) is not str or not uid: raise ContractError('registered UID malformed')
        if pending is None:
            pending_wire=()
        else:
            if type(pending) is not PendingUpdateV1:
                raise ContractError('pending update malformed')
            if (pending.version!=version+1 or pending.previous_digest!=digest or
                    pending.operation not in (REVOKE,ACTIVATE)):
                raise StateSynchronizationError('KGC pending predecessor mismatch')
            for label,value in (('pending handle',pending.handle),
                                ('pending update digest',pending.update_digest),
                                ('pending expected digest',pending.expected_digest)):
                require_bytes(value,label,32)
            pending_wire=(UInt64(pending.version),UInt32(pending.operation),
                pending.handle,pending.previous_digest,pending.protected.protected_record,
                pending.update_digest,pending.expected_digest)
        if status not in ('committed','pending','conflict'):
            raise ContractError('KGC status malformed')
        return encode((KGC_SCHEMA,self.sys_id,UInt64(version),digest,entries,
                       handles._canonical(),pending_wire,status,UInt64(generation)))

    def load(self):
        with self._lock:
            raw=self.path.read_bytes()
            if len(raw)<=28: raise AuthenticationError('sealed KGC state truncated')
            plain=AES256GCMSIV().decrypt(self._key,raw[:12],raw[12:],self._ad())
            obj=decode(plain)
            if (type(obj) is not tuple or len(obj)!=9 or obj[0]!=KGC_SCHEMA or
                    obj[1]!=self.sys_id or type(obj[2]) is not UInt64 or
                    type(obj[4]) is not tuple or type(obj[5]) is not tuple or
                    type(obj[6]) is not tuple or type(obj[8]) is not UInt64):
                raise ContractError('KGC snapshot schema mismatch')
            registered={}
            for entry in obj[4]:
                if type(entry) is not tuple or len(entry)!=2 or entry[0] in registered:
                    raise ContractError('KGC registration malformed')
                registered[entry[0]]=_handle(entry[1])
            handles=ExactRevocationSet(obj[5])
            p=obj[6]
            if len(p)==0: pending=None
            elif len(p)==7 and type(p[0]) is UInt64 and type(p[1]) is UInt32:
                pending=PendingUpdateV1(p[0].value,p[1].value,_handle(p[2]),p[3],
                    RevocationUpdate(p[4]),p[5],p[6])
            else: raise ContractError('KGC pending schema mismatch')
            if self._plain(obj[2].value,obj[3],registered,handles,pending,
                           obj[7],obj[8].value)!=plain:
                raise ContractError('noncanonical KGC snapshot')
            return obj[2].value,obj[3],registered,handles,pending,obj[7],obj[8].value

    def save(self,version,digest,registered,handles,pending,status,*,expected_version,
             expected_generation):
        with self._lock:
            if expected_version is None:
                generation=0
            else:
                current=self.load()
                if current[0]!=expected_version or current[6]!=expected_generation:
                    raise StateSynchronizationError('persistent KGC state changed')
                generation=current[6]+1
            plain=self._plain(version,digest,registered,handles,pending,status,generation)
            nonce=self._nonce_source(12)
            require_bytes(nonce,'KGC snapshot nonce',12)
            sealed=nonce+AES256GCMSIV().encrypt(self._key,nonce,plain,self._ad())
            self.path.parent.mkdir(parents=True,exist_ok=True)
            temp=self.path.with_name(self.path.name+'.'+secrets.token_hex(12)+'.tmp')
            try:
                with open(temp,'xb') as out:
                    out.write(sealed);out.flush();os.fsync(out.fileno())
                os.replace(str(temp),str(self.path))
                fd=os.open(str(self.path.parent),os.O_RDONLY)
                try: os.fsync(fd)
                finally: os.close(fd)
            finally:
                if temp.exists(): temp.unlink()
            return len(sealed),generation


class KGCRevocationManager:
    """Private UID registry and single pending slot; separate from TEE RevSet."""
    def __init__(self, sys_id, k_rev, admin_public, kgc_private, tee_ack_public,
                 state_store, *, metrics=None):
        require_bytes(k_rev, 'K_rev', 32)
        require_bytes(admin_public, 'admin public key', 32)
        require_bytes(tee_ack_public, 'TEE Ack public key', 32)
        self.sys_id = sys_id
        self._k_rev = k_rev
        self._admin_public = admin_public
        self._kgc_private = kgc_private
        self._tee_ack_public = tee_ack_public
        if type(state_store) is not EmulatedPersistentKGCStateStore or state_store.sys_id!=sys_id:
            raise ContractError('independent persistent KGC state required')
        self._state_store=state_store
        (self.version,self.digest,self._registered,self._handles,self.pending,
         self.status,self._generation)=state_store.load()
        if any(derive_revocation_handle(k_rev,sys_id,uid)!=handle
               for uid,handle in self._registered.items()):
            raise AuthenticationError('KGC RID key/registry mismatch')
        self._lock = threading.RLock()
        self.metrics = metrics

    def register(self, uid):
        with self._lock:
            if uid in self._registered: raise ProtocolRejectedError('UID already registered')
            updated=dict(self._registered)
            updated[uid]=derive_revocation_handle(self._k_rev,self.sys_id,uid)
            _,generation=self._state_store.save(self.version,self.digest,updated,self._handles,
                self.pending,self.status,expected_version=self.version,
                expected_generation=self._generation)
            self._registered=updated
            self._generation=generation
            if self.metrics is not None: self.metrics.n_registered += 1

    def rev(self, uid, operation, admin_signature, kgc_channel):
        with self._lock:
            verify_canonical(self._admin_public, admin_signature, 'MYABE-REV-MGMT',
                             *management_fields(self.sys_id, uid, operation, self.version))
            if self.pending is not None: raise ProtocolRejectedError('pending update exists')
            if uid not in self._registered: raise ProtocolRejectedError('UID not registered')
            handle = self._registered[uid]
            next_set = self._handles.with_operation(operation, handle)
            version = self.version + 1
            plain = delta_plaintext(self.sys_id, version, operation, handle, self.digest)
            signature = sign_canonical(self._kgc_private, 'MYABE-REV-DELTA', plain)
            record = kgc_channel.send(encode(('MYABE-REV-SIGNED', plain, signature)))
            protected = RevocationUpdate(record_wire(record))
            pending = PendingUpdateV1(version, operation, handle, self.digest, protected,
                hashlib.sha256(plain).digest(), state_digest(self.sys_id, version, next_set))
            _,generation=self._state_store.save(self.version,self.digest,self._registered,
                self._handles,pending,'pending',expected_version=self.version,
                expected_generation=self._generation)
            self.pending = pending
            self.status = 'pending'
            self._generation=generation
            if self.metrics is not None:
                if operation == REVOKE: self.metrics.rev_operations += 1
                else: self.metrics.activate_operations += 1
                self.metrics.delta_bytes += len(protected.protected_record)
            return protected

    def commit_ack(self, ack, coordinator):
        with self._lock:
            pending = self.pending
            if pending is None: raise ProtocolRejectedError('no pending update')
            try:
                verify_ack(ack, self._tee_ack_public)
                if (ack.sys_id != self.sys_id or ack.version != pending.version or
                    ack.update_digest != pending.update_digest or
                    ack.new_state_digest != pending.expected_digest):
                    raise ProtocolRejectedError('Ack/pending mismatch')
                coordinator.commit_revocation(self.version, self.digest, ack)
            except (AuthenticationError,ProtocolRejectedError,ContractError):
                self.status = 'conflict'
                _,generation=self._state_store.save(self.version,self.digest,
                    self._registered,self._handles,pending,'conflict',
                    expected_version=self.version,expected_generation=self._generation)
                self._generation=generation
                raise
            updated=self._handles.with_operation(pending.operation,pending.handle)
            _,generation=self._state_store.save(pending.version,pending.expected_digest,
                self._registered,updated,None,'committed',expected_version=self.version,
                expected_generation=self._generation)
            self._handles=updated
            self.version, self.digest, self.pending = pending.version, pending.expected_digest, None
            self.status = 'committed'
            self._generation=generation
            if self.metrics is not None:
                self.metrics.rev_version = self.version
                self.metrics.revset_size = self._handles._size()

    def registered_count(self):
        return len(self._registered)


class TEERevocationEngine:
    """TEE-side update verification and exact lookup over sealed local state."""
    def __init__(self, store, k_rev, kgc_public, ack_private, *, metrics=None):
        require_bytes(k_rev, 'K_rev', 32)
        require_bytes(kgc_public, 'KGC update public key', 32)
        self.store, self._k_rev = store, k_rev
        self._kgc_public, self._ack_private = kgc_public, ack_private
        self._lock = threading.RLock()
        self.metrics = metrics

    def rev_state_upt(self, protected, tee_channel):
        if type(protected) is not RevocationUpdate:
            raise ContractError('protected RevocationUpdate required')
        update_hash = hashlib.sha256(protected.protected_record).digest()
        with self._lock:
            state = self.store.load()
            for cached_hash, cached_ack in state.replay_acks:
                if hmac.compare_digest(update_hash, cached_hash):
                    return parse_ack(cached_ack)
            record = parse_record(protected.protected_record)
            signed = decode(tee_channel.receive(record))
            if (type(signed) is not tuple or len(signed) != 3 or
                    signed[0] != 'MYABE-REV-SIGNED'):
                raise ContractError('signed delta schema mismatch')
            plain, signature = signed[1:]
            verify_canonical(self._kgc_public, signature, 'MYABE-REV-DELTA', plain)
            sys_id, version, operation, handle, predecessor = parse_delta(plain)
            if sys_id != state.sys_id or version != state.rev_version + 1 or predecessor != state.state_digest:
                raise StateSynchronizationError('delta version/predecessor mismatch')
            next_set = state.revset.with_operation(operation, handle)
            digest = state_digest(sys_id, version, next_set)
            ack = sign_ack(self._ack_private, sys_id, version, hashlib.sha256(plain).digest(), digest)
            updated = RevocationState(sys_id, version, next_set, digest,
                                      state.replay_acks + ((update_hash, ack_wire(ack)),))
            snapshot_bytes = self.store.save(updated, expected_version=state.rev_version)
            if self.metrics is not None:
                self.metrics.rev_state_updates += 1
                self.metrics.state_snapshot_bytes = snapshot_bytes
            return ack

    def check_active(self, uid, permit):
        state = self.store.load()
        if self.metrics is not None:
            self.metrics.state_digest_checks += 1
        if (state.sys_id != permit.sys_id or state.rev_version != permit.rev_version or
                state.state_digest != permit.state_digest):
            if self.metrics is not None:
                self.metrics.sync_failures += 1
                if state.rev_version < permit.rev_version:
                    self.metrics.sync_requests += 1
                    # A lower local version can be either rollback or freeze;
                    # their cause cannot be inferred from this observation.
                    self.metrics.stale_local_detections += 1
            raise StateSynchronizationError('local state stale, ahead, or forked')
        if self.metrics is not None: self.metrics.rev_lookup_count += 1
        if state.revset.contains(derive_revocation_handle(self._k_rev, state.sys_id, uid)):
            if self.metrics is not None: self.metrics.revoked_rejections += 1
            raise ProtocolRejectedError('revoked')
        return state


class LinearizedCurrentHeadCoordinator:
    """One-process locked current head; no distributed or hardware freshness."""
    def __init__(self, initial_state, ack_public, head_store, *, nonce_source=None,
                 permit_key=None, metrics=None):
        initial_state.validate()
        require_bytes(ack_public, 'TEE Ack public key', 32)
        self.sys_id = initial_state.sys_id
        self.version = initial_state.rev_version
        self.digest = initial_state.state_digest
        self._lock = threading.RLock()
        self._nonce_source = secrets.token_bytes if nonce_source is None else nonce_source
        self._permit_key = secrets.token_bytes(32) if permit_key is None else permit_key
        require_bytes(self._permit_key,'coordinator permit key',32)
        self._ack_public = ack_public
        if (type(head_store) is not EmulatedPersistentCurrentHeadStore or
                head_store.sys_id != self.sys_id):
            raise ContractError('independent persistent head store required')
        self._head_store = head_store
        if head_store.load() != (self.version,self.digest):
            raise StateSynchronizationError('initial current head mismatch')
        self._seen_txn = set()
        self._active_txn_id = None
        self.authorization_commits = 0
        self.revocation_commits = 0
        self.metrics = metrics

    @contextmanager
    def authorization_transaction(self, *, sys_id, fresh_nonce):
        self._lock.acquire()
        try:
            if sys_id != self.sys_id: raise StateSynchronizationError('coordinator SysID mismatch')
            if self._head_store.load() != (self.version,self.digest):
                raise StateSynchronizationError('persistent current head mismatch')
            require_bytes(fresh_nonce, 'request nonce')
            if len(fresh_nonce) < 32: raise ContractError('request nonce too short')
            txn_id = self._nonce_source(32)
            require_bytes(txn_id, 'coordinator challenge', 32)
            if txn_id in self._seen_txn: raise StateSynchronizationError('coordinator challenge reused')
            if self._active_txn_id is not None:
                raise StateSynchronizationError('nested coordinator transaction rejected')
            self._seen_txn.add(txn_id)
            self._active_txn_id = txn_id
            if self.metrics is not None: self.metrics.authorization_txn_begin += 1
            coordinator = self
            class Transaction:
                def __init__(self): self._committed = False; self._closed = False
                def current_head(self):
                    if self._committed or self._closed:
                        raise StateSynchronizationError('permit already consumed')
                    record = hmac.new(coordinator._permit_key,
                        encode(('MYABE-CURRENT-HEAD',sys_id,UInt64(coordinator.version),
                                coordinator.digest,fresh_nonce,txn_id)),hashlib.sha256).digest()
                    return CurrentHeadPermit(sys_id,fresh_nonce,coordinator.version,
                        coordinator.digest,txn_id,record,True)
                def commit_authorization(self, request_nonce, bundle_digest):
                    require_bytes(bundle_digest, 'bundle digest', 32)
                    if (self._committed or self._closed or request_nonce != fresh_nonce or
                            coordinator._active_txn_id != txn_id):
                        raise StateSynchronizationError('authorization transaction invalid')
                    if coordinator._head_store.load() != (coordinator.version,
                                                          coordinator.digest):
                        raise StateSynchronizationError('head changed during authorization')
                    self._committed = True
                    coordinator.authorization_commits += 1
                    if coordinator.metrics is not None:
                        coordinator.metrics.authorization_txn_commit += 1
            transaction = Transaction()
            try: yield transaction
            finally:
                if not transaction._committed and self.metrics is not None:
                    self.metrics.authorization_txn_abort += 1
                transaction._closed = True
                self._active_txn_id = None
        finally:
            self._lock.release()

    def verify_permit(self, permit):
        if type(permit) is not CurrentHeadPermit:
            raise StateSynchronizationError('permit shape mismatch')
        with self._lock:
            if (not permit.active or permit.sys_id != self.sys_id or
                    permit.rev_version != self.version or permit.state_digest != self.digest or
                    permit.transaction_id != self._active_txn_id):
                raise StateSynchronizationError('permit/head mismatch')
            expected = hmac.new(self._permit_key,
                encode(('MYABE-CURRENT-HEAD',permit.sys_id,UInt64(permit.rev_version),
                        permit.state_digest,permit.fresh_nonce,permit.transaction_id)),
                hashlib.sha256).digest()
            if not hmac.compare_digest(expected,permit.authenticated_record):
                raise StateSynchronizationError('permit authentication failed')
            return permit

    def commit_revocation(self, old_version, old_digest, ack):
        with self._lock:
            verify_ack(ack, self._ack_public)
            if (ack.sys_id==self.sys_id and self.version==ack.version and
                    self.digest==ack.new_state_digest and
                    old_version+1==ack.version and
                    self._head_store.load()==(self.version,self.digest) and
                    self._head_store.transition()==(old_digest,ack.update_digest)):
                return  # Recovery after head commit but before KGC snapshot commit.
            if (ack.sys_id != self.sys_id or old_version != self.version or
                old_digest != self.digest or ack.version != self.version + 1):
                if self.metrics is not None: self.metrics.coordinator_conflicts += 1
                raise StateSynchronizationError('coordinator head conflict')
            self._head_store.save(ack.version,ack.new_state_digest,
                expected_version=self.version,expected_digest=self.digest,
                predecessor_digest=old_digest,update_digest=ack.update_digest)
            self.version, self.digest = ack.version, ack.new_state_digest
            self.revocation_commits += 1
