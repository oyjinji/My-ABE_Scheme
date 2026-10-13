from dataclasses import replace
import pytest
from core.myabe08.crypto import AES256GCMSIV, derive_dem_key, dem_encrypt, dem_decrypt
from core.myabe08.encoding import encode_dem_ad
from core.myabe08.errors import AuthenticationError, ContractError


def flip(data):
    return bytes([data[0]^1])+data[1:]


def test_rfc8452_appendix_c2_aes256_nonempty_vector():
    # External published KAT, not computed from this implementation.
    key, nonce, plain = b'\x01'+bytes(31), b'\x03'+bytes(11), b'\x01'+bytes(7)
    expected = bytes.fromhex('c2ef328e5c71c83b843122130f7364b761e0b97427e3df28')
    adapter = AES256GCMSIV()
    assert adapter.encrypt(key,nonce,plain,b'') == expected
    assert adapter.decrypt(key,nonce,expected,b'') == plain


def test_aead_roundtrip_and_every_authentication_mismatch():
    a,key,nonce,ad = AES256GCMSIV(),bytes(32),bytes(12),b'ad'
    ct = a.encrypt(key,nonce,b'protected payload',ad)
    assert len(ct) == len(b'protected payload')+16
    assert a.decrypt(key,nonce,ct,ad) == b'protected payload'
    for k,n,c,d in [
        (flip(key),nonce,ct,ad), (key,flip(nonce),ct,ad), (key,nonce,ct,b'wrong'),
        (key,nonce,flip(ct),ad), (key,nonce,ct[:-1]+bytes([ct[-1]^1]),ad),
        (key,nonce,ct[:-1],ad), (key,nonce,ct[:15],ad),
    ]:
        with pytest.raises(AuthenticationError):a.decrypt(k,n,c,d)


@pytest.mark.parametrize('key,nonce', [(bytes(16),bytes(12)),(bytes(32),bytes(11)),(bytearray(32),bytes(12))])
def test_aead_parameter_widths(key,nonce):
    with pytest.raises(ContractError):AES256GCMSIV().encrypt(key,nonce,b'm',b'a')


def test_empty_message_is_explicit_library_limitation():
    with pytest.raises(ContractError,match='nonempty plaintext'):
        AES256GCMSIV().encrypt(bytes(32),bytes(12),b'',b'')


def test_dem_fresh_random_nonce_and_context_binding():
    # Canonical GT identity is allowed as a primitive fixture, not an ABE key.
    e = (1).to_bytes(48,'big') + bytes(528)
    ctx = b'c'*32
    sealed = [dem_encrypt(ctx,e,b'message') for _ in range(8)]
    assert len({x.nonce for x in sealed}) == 8  # finite RNG sample, no no-collision theorem
    assert all(len(x.nonce)==12 for x in sealed)
    assert all(dem_decrypt(ctx,e,x)==b'message' for x in sealed)
    with pytest.raises(AuthenticationError):dem_decrypt(b'x'*32,e,sealed[0])
    with pytest.raises(AuthenticationError):dem_decrypt(ctx,e,replace(sealed[0],ciphertext=flip(sealed[0].ciphertext)))
    with pytest.raises(AuthenticationError):
        AES256GCMSIV().decrypt(derive_dem_key(ctx,e),sealed[0].nonce,sealed[0].ciphertext,encode_dem_ad(b'x'*32))
    with pytest.raises(ContractError):derive_dem_key(ctx,bytes(575))
