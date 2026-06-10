'''
Opaque bytes file encryption helpers for DACP dataset experiments.
'''

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_dataset_key():
    return os.urandom(32)


def derive_file_key(dataset_key, dataset_id, context=b""):
    if not isinstance(dataset_key, bytes) or len(dataset_key) != 32:
        raise ValueError('dataset_key must be 32 bytes')
    if isinstance(context, str):
        context = context.encode('utf-8')
    digest = hashlib.sha256()
    digest.update(b'dacp::dataset-file-key::')
    digest.update(dataset_key)
    digest.update(str(dataset_id).encode('utf-8'))
    digest.update(context or b'')
    return digest.digest()


def encrypt_file_bytes(plaintext, dataset_key, aad):
    if not isinstance(plaintext, bytes):
        raise TypeError('encrypt_file_bytes requires bytes plaintext')
    aad = _aad_bytes(aad)
    dataset_id = _dataset_id_from_aad(aad)
    key = derive_file_key(dataset_key, dataset_id, context=aad)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        'mode': 'AESGCM',
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex(),
        'aad': aad.decode('utf-8', errors='replace'),
        'plaintext_size': len(plaintext),
        'ciphertext_size': len(ciphertext),
    }


def decrypt_file_bytes(cipher_obj, dataset_key, aad):
    aad = _aad_bytes(aad)
    dataset_id = _dataset_id_from_aad(aad)
    key = derive_file_key(dataset_key, dataset_id, context=aad)
    try:
        nonce = bytes.fromhex(cipher_obj['nonce'])
        ciphertext = bytes.fromhex(cipher_obj['ciphertext'])
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


def _aad_bytes(aad):
    if isinstance(aad, bytes):
        return aad
    if isinstance(aad, bytearray):
        return bytes(aad)
    if isinstance(aad, str):
        return aad.encode('utf-8')
    raise TypeError('aad must be bytes or str')


def _dataset_id_from_aad(aad):
    text = aad.decode('utf-8', errors='replace')
    for part in text.split('|'):
        if part.startswith('dataset_id='):
            return part.split('=', 1)[1]
    return 'unknown-dataset'
