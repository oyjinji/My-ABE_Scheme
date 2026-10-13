import hashlib
import hmac
import inspect
import pytest
from core.myabe08.crypto import (
    sha256_digest, context_hash, compute_ctx_priv, contextual_token,
    derive_row_key, derive_af_nonce, derive_af_nonce_material,
)
from core.myabe08.encoding import encode, encode_attribute, UInt64
from core.myabe08.errors import ContractError


def test_sha_and_context_exact_bytes():
    assert sha256_digest(b'abc').hex() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    assert context_hash(b'abc') == hashlib.sha256(b'abc').digest()
    assert compute_ctx_priv(b'sys',bytes(32),7) == hashlib.sha256(encode(('PRIV',b'sys',bytes(32),UInt64(7)))).digest()


def test_shared_policy_user_prf_and_sample_context_separation():
    key, attr = bytes(range(32)), encode_attribute('test','role','reader')
    context = compute_ctx_priv(b'sys',bytes(32),1)
    token = contextual_token(key,b'sys',context,attr)
    assert token == hmac.new(key,encode(('MYABE-TOK',b'sys',context,attr)),hashlib.sha256).digest()
    assert token == contextual_token(key,b'sys',context,attr)
    # Finite sample collision observation ONLY, not an unlinkability proof.
    values = {contextual_token(key,b'sys',compute_ctx_priv(b'sys',bytes(32),i),attr) for i in range(16)}
    assert len(values) == 16
    assert not {'role','session','nonce'} & set(inspect.signature(contextual_token).parameters)


def test_row_and_nonce_domains_and_lengths():
    context, token = bytes(32), b't'*32
    key = derive_row_key(context,token)
    material = derive_af_nonce_material(context,token)
    assert key != material
    assert len(key) == 32 and len(material) == 32
    assert derive_af_nonce(context,token) == material[:12]
    assert derive_af_nonce(context,token) == derive_af_nonce(context,token)
    assert key != derive_row_key(b'c'*32,token)


@pytest.mark.parametrize('key', [bytes(31),bytes(33),bytearray(32)])
def test_exact_prf_key_width(key):
    with pytest.raises(ContractError):
        contextual_token(key,b'sys',bytes(32),encode_attribute('n','a','v'))


def test_wrong_context_token_or_attribute_rejected():
    for fn in (derive_row_key,derive_af_nonce):
        with pytest.raises(ContractError):fn(bytes(31),bytes(32))
        with pytest.raises(ContractError):fn(bytes(32),bytes(31))
    with pytest.raises(ContractError):
        contextual_token(bytes(32),b'sys',bytes(32),b'not-a-canonical-attribute')
    with pytest.raises(ContractError):sha256_digest('abc')
