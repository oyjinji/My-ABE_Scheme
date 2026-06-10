'''
Stable dataset manifest for DACP data experiments.

The manifest stores hashes, sizes, chunk metadata, and policy metadata. It does
not store plaintext dataset contents.
'''

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime


@dataclass
class ChunkRecord:
    chunk_id: str
    plaintext_sha256: str
    ciphertext_sha256: str
    plaintext_size: int
    ciphertext_size: int
    nonce: str
    aad: str
    offset: int = None


@dataclass
class DatasetManifest:
    dataset_id: str
    dataset_name: str
    domain: str
    source_path: str
    policy_str: str
    file_name: str
    file_size: int
    plaintext_sha256: str
    encrypted_size: int
    chunks: list
    created_at: str
    version: int = 1


def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def make_dataset_id(dataset_name, file_sha256):
    payload = '{0}|{1}'.format(dataset_name, file_sha256).encode('utf-8')
    return hashlib.sha256(b'dacp::dataset::' + payload).hexdigest()[:32]


def manifest_to_dict(manifest):
    obj = asdict(manifest)
    obj['chunks'] = [
        asdict(chunk) if isinstance(chunk, ChunkRecord) else dict(chunk)
        for chunk in manifest.chunks
    ]
    return obj


def manifest_from_dict(obj):
    chunks = [
        chunk if isinstance(chunk, ChunkRecord) else ChunkRecord(**chunk)
        for chunk in obj.get('chunks', [])
    ]
    value = dict(obj)
    value['chunks'] = chunks
    return DatasetManifest(**value)


def save_manifest(manifest, path):
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(manifest_to_dict(manifest), handle, sort_keys=True, indent=2)
        handle.write('\n')


def load_manifest(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return manifest_from_dict(json.load(handle))
