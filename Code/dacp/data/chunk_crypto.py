'''
Generic binary chunk encryption for DACP dataset experiments.
'''

import json
from pathlib import Path

from .file_crypto import decrypt_file_bytes, encrypt_file_bytes
from .manifest import ChunkRecord, sha256_bytes, sha256_file


def iter_file_chunks(path, chunk_size):
    offset = 0
    with open(path, 'rb') as handle:
        while True:
            chunk = handle.read(int(chunk_size))
            if not chunk:
                break
            yield offset, chunk
            offset += len(chunk)


def encrypt_file_in_chunks(input_path, output_dir, dataset_key, dataset_id,
                           chunk_size=16 * 1024 * 1024):
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    records = []
    total_ciphertext_size = 0

    for index, (offset, plaintext) in enumerate(iter_file_chunks(input_path, chunk_size)):
        chunk_id = 'chunk-{0:06d}'.format(index)
        aad = 'dataset_id={0}|chunk_id={1}|offset={2}'.format(dataset_id, chunk_id, offset)
        cipher_obj = encrypt_file_bytes(plaintext, dataset_key, aad.encode('utf-8'))
        payload = {
            'chunk_id': chunk_id,
            'cipher': cipher_obj,
        }
        out_path = output_dir / (chunk_id + '.json')
        with open(out_path, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, sort_keys=True, indent=2)
            handle.write('\n')
        ciphertext_bytes = bytes.fromhex(cipher_obj['ciphertext'])
        total_ciphertext_size += len(ciphertext_bytes)
        records.append(ChunkRecord(
            chunk_id=chunk_id,
            plaintext_sha256=sha256_bytes(plaintext),
            ciphertext_sha256=sha256_bytes(ciphertext_bytes),
            plaintext_size=len(plaintext),
            ciphertext_size=len(ciphertext_bytes),
            nonce=cipher_obj['nonce'],
            aad=aad,
            offset=offset,
        ))

    return records, total_ciphertext_size


def decrypt_chunks_to_file(manifest, encrypted_dir, output_path, dataset_key):
    encrypted_dir = Path(encrypted_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'wb') as out:
        for record in sorted(manifest.chunks, key=lambda item: item.offset or 0):
            path = encrypted_dir / (record.chunk_id + '.json')
            with open(path, 'r', encoding='utf-8') as handle:
                payload = json.load(handle)
            plaintext = decrypt_file_bytes(
                payload['cipher'],
                dataset_key,
                record.aad.encode('utf-8'),
            )
            if plaintext is None:
                raise ValueError('failed to decrypt chunk {0}'.format(record.chunk_id))
            if sha256_bytes(plaintext) != record.plaintext_sha256:
                raise ValueError('plaintext hash mismatch for chunk {0}'.format(record.chunk_id))
            out.write(plaintext)
    return sha256_file(output_path)
