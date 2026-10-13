"""Read-only Phase 3B regression bytes. All fixed keys and nonces are TEST-only."""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.myabe08.attestation import EmulatedAttestationEvidence, evidence_digest
from core.myabe08.channel import CHANNEL_INFO, x25519_private_from_seed, x25519_public_bytes
from core.myabe08.crypto import AES256GCMSIV
from core.myabe08.encoding import StructuredRecord, decode, encode
from core.myabe08.profile import EMULATED_TEE_PROFILE
from core.myabe08.signing import private_key_from_seed, public_key_bytes, sign_canonical, verify_canonical

VECTOR = Path(__file__).parent / 'vectors' / 'profile_v1.json'
PRIOR_PROJECTION_SHA256 = 'dc4704e75ed5abc60586f1b5c4fd34466cbebd47b383b5d6368f194820d042df'


def _data():
    return json.loads(VECTOR.read_text())


def _raw(value):
    return bytes.fromhex(value)


def test_prior_frozen_vector_fields_unchanged():
    previous = {k: v for k, v in _data().items() if k not in ('phase3b','phase3c')}
    packed = json.dumps(previous, sort_keys=True, separators=(',', ':')).encode()
    assert hashlib.sha256(packed).hexdigest() == PRIOR_PROJECTION_SHA256


def test_ed25519_credential_cert_publication_possession_and_cap_bytes():
    v = _data()['phase3b']
    assert 'NOT PRODUCTION SECRET' in v['notice']
    keys = {role: private_key_from_seed(_raw(seed))
            for role, seed in v['ed25519_seeds_hex'].items()}
    assert {role: public_key_bytes(key).hex() for role, key in keys.items()} == v['ed25519_public_hex']
    credential = decode(_raw(v['credential_canonical_hex']))
    certificate = decode(_raw(v['do_cert_canonical_hex']))
    assert encode(credential).hex() == v['credential_canonical_hex']
    assert encode(certificate).hex() == v['do_cert_canonical_hex']
    assert credential[0] == 'MYABE-CRED' and certificate[0] == 'MYABE-DO-CERT'
    assert credential[1] == certificate[1] == _raw(v['sys_id_hex'])
    for role, message, signature_hex in (
            ('kgc', credential, v['credential_signature_hex']),
            ('kgc', certificate, v['do_cert_signature_hex'])):
        signature = _raw(signature_hex)
        assert sign_canonical(keys[role], message[0], *message[1:]) == signature
        verify_canonical(public_key_bytes(keys[role]), signature, message[0], *message[1:])
    publication = v['publication']
    message = (_raw(publication['header_digest_hex']),
               _raw(publication['dem_content_digest_hex']))
    assert hashlib.sha256(encode((_raw(publication['dem_nonce_hex']),
                                  _raw(publication['dem_ciphertext_hex'])))).hexdigest() == publication['dem_content_digest_hex']
    assert sign_canonical(keys['do'], 'MYABE-PUBLISH', *message).hex() == publication['signature_hex']
    envelope = decode(_raw(v['authorization_bytes_hex']))
    assert envelope[0] == 'MYABE-AUTH-ENVELOPE'
    bundle_wire, cap_fields, cap_signature = envelope[1:]
    assert encode(envelope).hex() == v['authorization_bytes_hex']
    assert hashlib.sha256(bundle_wire).hexdigest() == v['bundle_digest_hex']
    assert decode(bundle_wire)[0] == 'MYABE-BUNDLE'
    assert cap_fields[0] == _raw(v['sys_id_hex'])
    assert cap_fields[1] == message[0] and cap_fields[-1] == _raw(v['bundle_digest_hex'])
    assert cap_signature.hex() == v['capability_signature_hex']
    assert sign_canonical(keys['cap'], 'MYABE-AUTH', *cap_fields) == cap_signature
    verify_canonical(public_key_bytes(keys['cap']), cap_signature, 'MYABE-AUTH', *cap_fields)


def test_software_seal_attestation_channel_and_possession_vectors():
    v = _data()['phase3b']
    root = private_key_from_seed(_raw(v['ed25519_seeds_hex']['attestation_root']))
    e = decode(_raw(v['attestation']['evidence_canonical_hex']))
    assert e[0] == 'MYABE-EMULATED-ATTEST'
    assert e[1] == _raw(v['sys_id_hex']) and e[2] == EMULATED_TEE_PROFILE
    assert e[3] == _raw(v['attestation']['measurement_hex'])
    assert e[5] == _raw(v['attestation']['challenge_hex'])
    assert e[7] == _raw(v['attestation']['session_id_hex'])
    assert encode(e).hex() == v['attestation']['evidence_canonical_hex']
    signature = _raw(v['attestation']['signature_hex'])
    assert sign_canonical(root, e[0], *e[1:]) == signature
    verify_canonical(public_key_bytes(root), signature, e[0], *e[1:])
    evidence = EmulatedAttestationEvidence(e[1], e[2], e[3], e[4].value,
                                            e[5], e[6], e[7], signature)
    client = x25519_private_from_seed(_raw(v['channel']['client_x25519_seed_hex']))
    server = x25519_private_from_seed(_raw(v['channel']['server_x25519_seed_hex']))
    client_pub, server_pub = x25519_public_bytes(client), x25519_public_bytes(server)
    assert client_pub.hex() == v['channel']['client_public_hex']
    assert server_pub.hex() == v['channel']['server_public_hex'] == e[6].hex()
    transcript = encode(('MYABE-EMULATED-CHANNEL-TRANSCRIPT', e[1], e[2],
                         evidence_digest(evidence), client_pub, server_pub, e[5], e[7]))
    digest = hashlib.sha256(transcript).digest()
    assert digest.hex() == v['channel']['transcript_digest_hex']
    shared = client.exchange(X25519PublicKey.from_public_bytes(server_pub))
    assert shared == server.exchange(X25519PublicKey.from_public_bytes(client_pub))
    for direction, label in (('DU->TEE', 'du_to_tee_key_hex'),
                             ('TEE->DU', 'tee_to_du_key_hex')):
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=digest,
                   info=CHANNEL_INFO + b'|' + direction.encode()).derive(shared)
        assert key.hex() == v['channel'][label]
    assert v['channel']['du_to_tee_key_hex'] != v['channel']['tee_to_du_key_hex']
    auth_key = private_key_from_seed(_raw(v['ed25519_seeds_hex']['auth']))
    capability = decode(_raw(v['authorization_bytes_hex']))[2]
    possession_fields = (e[1], e[7], e[5], digest, server_pub,
                         capability[1], capability[4])
    proof = _raw(v['possession_signature_hex'])
    assert sign_canonical(auth_key, 'MYABE-DU-POSSESSION', *possession_fields) == proof
    verify_canonical(public_key_bytes(auth_key), proof,
                     'MYABE-DU-POSSESSION', *possession_fields)

    seal = v['sealed_blob']
    opaque, key, nonce = (_raw(seal['opaque_hex']), _raw(seal['key_hex']),
                          _raw(seal['test_nonce_hex']))
    assert opaque[:12] == nonce
    ad = encode(('MYABE-SEAL', _raw(v['sys_id_hex']), EMULATED_TEE_PROFILE,
                 'MYABE08-SEALED-USER-V1'))
    plaintext = AES256GCMSIV().decrypt(key, nonce, opaque[12:], ad)
    record = decode(plaintext)
    assert isinstance(record, StructuredRecord) and record.schema == 'MYABE08.SealedUserV1'
    assert encode(record) == plaintext
    assert dict(record.fields)['sys_id'] == _raw(v['sys_id_hex'])
    assert nonce + AES256GCMSIV().encrypt(key, nonce, plaintext, ad) == opaque
