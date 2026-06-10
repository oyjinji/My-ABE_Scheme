'''
Smoke tests for DACP dataset experiment scaffold.
'''

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Code.dacp.data import (
    AuditLog,
    ChunkRecord,
    DatasetManifest,
    decrypt_file_bytes,
    encrypt_file_bytes,
    generate_dataset_key,
    load_manifest,
    make_dataset_id,
    run_dataset_file_experiment,
    save_manifest,
    sha256_bytes,
    sha256_file,
)
from Code.dacp.data.chunk_crypto import decrypt_chunks_to_file, encrypt_file_in_chunks
from Code.dacp.data.manifest import utc_now_iso
from Code.dacp.data.policies import get_policy


def assert_true(name, condition):
    if not condition:
        raise AssertionError(name)
    print('{:<44} OK'.format(name))


def test_manifest_and_hashes(tmp):
    path = tmp / 'sample.bin'
    data = b'dacp data scaffold\n' * 8
    path.write_bytes(data)
    file_sha = sha256_file(path)
    assert_true('sha256_file/sha256_bytes', file_sha == sha256_bytes(data))
    dataset_id = make_dataset_id('sample', file_sha)
    manifest = DatasetManifest(
        dataset_id=dataset_id,
        dataset_name='sample',
        domain='test',
        source_path=str(path),
        policy_str=get_policy('credit_fraud'),
        file_name=path.name,
        file_size=len(data),
        plaintext_sha256=file_sha,
        encrypted_size=0,
        chunks=[ChunkRecord(
            chunk_id='file-000000',
            plaintext_sha256=file_sha,
            ciphertext_sha256='',
            plaintext_size=len(data),
            ciphertext_size=0,
            nonce='',
            aad='dataset_id=' + dataset_id,
            offset=0,
        )],
        created_at=utc_now_iso(),
    )
    out = tmp / 'manifest.json'
    save_manifest(manifest, out)
    loaded = load_manifest(out)
    assert_true('manifest save/load', loaded.dataset_id == dataset_id and loaded.chunks[0].chunk_id == 'file-000000')


def test_file_crypto(tmp):
    dataset_key = generate_dataset_key()
    assert_true('generate_dataset_key', isinstance(dataset_key, bytes) and len(dataset_key) == 32)
    plaintext = b'opaque dataset bytes'
    aad = b'dataset_id=test|chunk_id=file-000000'
    cipher_obj = encrypt_file_bytes(plaintext, dataset_key, aad)
    assert_true('encrypt_file_bytes shape', cipher_obj['mode'] == 'AESGCM' and len(cipher_obj['nonce']) == 24)
    recovered = decrypt_file_bytes(cipher_obj, dataset_key, aad)
    assert_true('decrypt_file_bytes', recovered == plaintext)
    assert_true('decrypt_file_bytes wrong aad', decrypt_file_bytes(cipher_obj, dataset_key, b'bad') is None)


def test_chunk_crypto(tmp):
    path = tmp / 'chunked.bin'
    path.write_bytes(b'0123456789abcdef' * 32)
    dataset_key = generate_dataset_key()
    dataset_id = 'chunk-test'
    encrypted_dir = tmp / 'chunks'
    records, encrypted_size = encrypt_file_in_chunks(
        path,
        encrypted_dir,
        dataset_key,
        dataset_id,
        chunk_size=37,
    )
    manifest = DatasetManifest(
        dataset_id=dataset_id,
        dataset_name='chunked',
        domain='test',
        source_path=str(path),
        policy_str=get_policy('credit_fraud'),
        file_name=path.name,
        file_size=path.stat().st_size,
        plaintext_sha256=sha256_file(path),
        encrypted_size=encrypted_size,
        chunks=records,
        created_at=utc_now_iso(),
    )
    recovered_path = tmp / 'recovered.bin'
    recovered_sha = decrypt_chunks_to_file(manifest, encrypted_dir, recovered_path, dataset_key)
    assert_true('chunk encrypt/decrypt', recovered_sha == sha256_file(path))


def test_audit(tmp):
    audit = AuditLog()
    audit.add_event('DATASET_REGISTERED', dataset_id='d')
    path = tmp / 'audit.json'
    audit.save_json(path)
    loaded = json.loads(path.read_text(encoding='utf-8'))
    assert_true('AuditLog save_json', loaded[0]['event_type'] == 'DATASET_REGISTERED')


def test_experiment(tmp):
    dataset_path = tmp / 'synthetic.csv'
    dataset_path.write_text(
        'id,amount,label\n1,10.00,0\n2,42.00,1\n',
        encoding='utf-8',
    )
    summary = run_dataset_file_experiment(
        dataset_path=dataset_path,
        dataset_name='Synthetic Scaffold CSV',
        domain='test',
        policy_str=get_policy('credit_fraud'),
        output_dir=tmp / 'experiment',
        chunk_mode=False,
    )
    assert_true('experiment key recovered', summary['dacp_key_recover_success'])
    assert_true('experiment dataset recovered', summary['dataset_recover_success'])
    assert_true('experiment sha match', summary['plaintext_sha256'] == summary['recovered_sha256'])


def main():
    with tempfile.TemporaryDirectory() as work:
        tmp = Path(work)
        test_manifest_and_hashes(tmp)
        test_file_crypto(tmp)
        test_chunk_crypto(tmp)
        test_audit(tmp)
        test_experiment(tmp)
    print('=' * 72)
    print('DACP data scaffold tests passed.')


if __name__ == '__main__':
    main()
