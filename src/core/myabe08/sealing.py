"""Software authenticated sealing emulation; no hardware isolation or rollback resistance."""
import secrets

from .crypto import AES256GCMSIV
from .credential import credential_digest
from .encoding import StructuredRecord, UInt64, decode, encode, require_bytes
from .errors import ContractError, ProtocolRejectedError
from .profile import EMULATED_TEE_PROFILE
from .types import SealedUserBlob, UserBaseState

SCHEMA_VERSION='MYABE08-SEALED-USER-V1'


def _sealed_record(base,backend,profile_id=EMULATED_TEE_PROFILE):
    if type(base) is not UserBaseState:
        raise ContractError('UserBaseState required')
    if base.sys_id!=backend.binding.sys_id or base.profile_id!=profile_id or base.schema_version!=SCHEMA_VERSION:
        raise ContractError('sealed state binding mismatch')
    require_bytes(base.credential_digest,'credential digest',32)
    if type(base.uid_handle) is not str or not base.uid_handle:
        raise ContractError('UID required')
    if type(base.credential_version) is not int or base.credential_version<1:
        raise ContractError('credential version required')
    return StructuredRecord('MYABE08.SealedUserV1',(
        ('sys_id',base.sys_id),('uid_handle',base.uid_handle),
        ('mu',backend.serialize_scalar(base.mu)),
        ('k0',backend.serialize_g2(base.k0,allow_identity=False)),
        ('credential_digest',base.credential_digest),
        ('credential_version',UInt64(base.credential_version)),
        ('schema_version',base.schema_version),('profile_id',base.profile_id)))


class EmulatedSealingService:
    def __init__(self,key,backend,*,schema_version=SCHEMA_VERSION,nonce_source=None,
                 profile_id=EMULATED_TEE_PROFILE):
        require_bytes(key,'independent K_seal',32)
        if schema_version!=SCHEMA_VERSION: raise ContractError('unsupported seal schema')
        self._key=key
        self._backend=backend
        self.schema_version=schema_version
        self.profile_id=profile_id
        self._nonce_source=secrets.token_bytes if nonce_source is None else nonce_source

    def _ad(self):
        return encode(('MYABE-SEAL',self._backend.binding.sys_id,
                       self.profile_id,self.schema_version))

    def seal(self,base):
        plaintext=encode(_sealed_record(base,self._backend,self.profile_id))
        nonce=self._nonce_source(12)
        require_bytes(nonce,'fresh seal nonce',12)
        sealed=AES256GCMSIV().encrypt(self._key,nonce,plaintext,self._ad())
        return SealedUserBlob(nonce+sealed)

    def unseal(self,blob,credential):
        if type(blob) is not SealedUserBlob or len(blob.opaque)<=28:
            raise ContractError('opaque sealed blob required')
        nonce,ciphertext=blob.opaque[:12],blob.opaque[12:]
        raw=AES256GCMSIV().decrypt(self._key,nonce,ciphertext,self._ad())
        record=decode(raw)
        names=('sys_id','uid_handle','mu','k0','credential_digest',
               'credential_version','schema_version','profile_id')
        if (type(record) is not StructuredRecord or record.schema!='MYABE08.SealedUserV1'
                or tuple(name for name,_ in record.fields)!=names or encode(record)!=raw):
            raise ContractError('noncanonical sealed state')
        values=dict(record.fields)
        version=values['credential_version']
        if type(version) is not UInt64:
            raise ContractError('sealed version field malformed')
        base=UserBaseState(values['sys_id'],values['uid_handle'],
            self._backend.deserialize_scalar(values['mu'],binding=self._backend.binding,allow_zero=False),
            self._backend.deserialize_g2(values['k0'],binding=self._backend.binding,allow_identity=False),
            values['credential_digest'],version.value,values['schema_version'],values['profile_id'])
        _sealed_record(base,self._backend,self.profile_id)
        if (base.uid_handle!=credential.uid or base.credential_digest!=credential_digest(credential)
                or base.credential_version!=credential.credential_version):
            raise ProtocolRejectedError('sealed credential binding mismatch')
        return base
