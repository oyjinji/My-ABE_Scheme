'''
Local dataset-file experiment runner for DACP.

The dataset is treated as opaque bytes. No real dataset-specific parsing,
schema interpretation, HTTP, socket, or database layer is performed here.
'''

import json
import time
from pathlib import Path

from charm.toolbox.pairinggroup import PairingGroup

from Code.dacp import DACPCPABE
from Code.dacp.components import (
    AESGCMEnvelope,
    BlindPairingOPRF,
    Ed25519Signature,
    PrototypeCertificateAuthority,
)
from Code.dacp.protocol import (
    ACCESS_REQUEST,
    CIPHERTEXT_UPLOAD,
    OPRF_REQUEST,
    OPRF_RESPONSE,
    TK_PROVISION,
    TRANSFORM_RESPONSE,
    USER_KEY_REQUEST,
    USER_KEY_RESPONSE,
    CloudServiceProvider,
    DataOwner,
    DataUser,
    KGC,
    LocalTransport,
    ProtocolMetrics,
    WireCodec,
    new_session_id,
)

from .audit import AuditLog
from .chunk_crypto import decrypt_chunks_to_file, encrypt_file_in_chunks
from .file_crypto import decrypt_file_bytes, encrypt_file_bytes, generate_dataset_key
from .manifest import (
    ChunkRecord,
    DatasetManifest,
    make_dataset_id,
    save_manifest,
    sha256_bytes,
    sha256_file,
    utc_now_iso,
)
from .policies import to_charm_policy
from .summary import save_summary_json


def run_dataset_file_experiment(
        dataset_path,
        dataset_name,
        domain,
        policy_str,
        output_dir,
        oprf_mode="blind",
        sig_mode="ed25519",
        symmetric_mode="aesgcm",
        wire_mode="json",
        chunk_mode=False,
        chunk_size=16 * 1024 * 1024,
        buyer_attrs=None):
    if symmetric_mode != 'aesgcm':
        raise ValueError('dataset experiments require symmetric_mode="aesgcm"')

    started = time.time()
    dataset_path = Path(dataset_path)
    if not dataset_path.exists():
        raise FileNotFoundError('dataset file does not exist: {0}'.format(dataset_path))

    output_dir = Path(output_dir)
    encrypted_dir = output_dir / 'encrypted'
    recovered_dir = output_dir / 'recovered'
    output_dir.mkdir(parents=True, exist_ok=True)
    encrypted_dir.mkdir(parents=True, exist_ok=True)
    recovered_dir.mkdir(parents=True, exist_ok=True)

    audit = AuditLog()
    plaintext_sha = sha256_file(dataset_path)
    file_size = dataset_path.stat().st_size
    dataset_id = make_dataset_id(dataset_name, plaintext_sha)
    dataset_key = generate_dataset_key()
    audit.add_event(
        'DATASET_REGISTERED',
        dataset_id=dataset_id,
        dataset_name=dataset_name,
        source_path=str(dataset_path),
        plaintext_sha256=plaintext_sha,
        file_size=file_size,
    )

    encrypt_started = time.time()
    if chunk_mode:
        chunk_dir = encrypted_dir / (dataset_id + '_chunks')
        chunk_records, encrypted_size = encrypt_file_in_chunks(
            dataset_path,
            chunk_dir,
            dataset_key,
            dataset_id,
            chunk_size=chunk_size,
        )
        encrypted_path = chunk_dir
    else:
        plaintext = dataset_path.read_bytes()
        aad = 'dataset_id={0}|chunk_id=file-000000|sha256={1}'.format(
            dataset_id,
            plaintext_sha,
        )
        cipher_obj = encrypt_file_bytes(plaintext, dataset_key, aad.encode('utf-8'))
        encrypted_path = encrypted_dir / (dataset_id + '.file.json')
        with open(encrypted_path, 'w', encoding='utf-8') as handle:
            json.dump(cipher_obj, handle, sort_keys=True, indent=2)
            handle.write('\n')
        ciphertext_bytes = bytes.fromhex(cipher_obj['ciphertext'])
        encrypted_size = len(ciphertext_bytes)
        chunk_records = [ChunkRecord(
            chunk_id='file-000000',
            plaintext_sha256=sha256_bytes(plaintext),
            ciphertext_sha256=sha256_bytes(ciphertext_bytes),
            plaintext_size=len(plaintext),
            ciphertext_size=encrypted_size,
            nonce=cipher_obj['nonce'],
            aad=aad,
            offset=0,
        )]
    dataset_encrypt_time = time.time() - encrypt_started

    manifest = DatasetManifest(
        dataset_id=dataset_id,
        dataset_name=dataset_name,
        domain=domain,
        source_path=str(dataset_path),
        policy_str=policy_str,
        file_name=dataset_path.name,
        file_size=file_size,
        plaintext_sha256=plaintext_sha,
        encrypted_size=encrypted_size,
        chunks=chunk_records,
        created_at=utc_now_iso(),
    )
    manifest_path = output_dir / (dataset_id + '.manifest.json')
    save_manifest(manifest, manifest_path)
    audit.add_event(
        'DATASET_ENCRYPTED',
        dataset_id=dataset_id,
        chunk_mode=bool(chunk_mode),
        encrypted_path=str(encrypted_path),
        encrypted_size=encrypted_size,
        num_chunks=len(chunk_records),
    )

    dacp_policy_str = to_charm_policy(policy_str)
    protocol_result = _encrypt_dataset_key_with_dacp(
        dataset_key,
        dacp_policy_str,
        oprf_mode=oprf_mode,
        sig_mode=sig_mode,
        wire_mode=wire_mode,
        buyer_attrs=buyer_attrs,
    )
    recovered_dataset_key = protocol_result['recovered_dataset_key']
    dacp_key_recover_success = recovered_dataset_key == dataset_key
    audit.add_event(
        'DACP_KEY_ENCRYPTED',
        dataset_id=dataset_id,
        ct_id=protocol_result['ct_id'],
        external_oprf_tokens_used=protocol_result['external_oprf_tokens_used'],
    )
    audit.add_event(
        'CSP_TRANSFORMED',
        dataset_id=dataset_id,
        matched_candidates=protocol_result['matched_candidates'],
    )
    audit.add_event(
        'DU_FINAL_DECRYPTED',
        dataset_id=dataset_id,
        dacp_key_recover_success=dacp_key_recover_success,
    )

    recovered_path = recovered_dir / dataset_path.name
    decrypt_started = time.time()
    if dacp_key_recover_success:
        if chunk_mode:
            recovered_sha = decrypt_chunks_to_file(
                manifest,
                encrypted_path,
                recovered_path,
                recovered_dataset_key,
            )
        else:
            with open(encrypted_path, 'r', encoding='utf-8') as handle:
                cipher_obj = json.load(handle)
            recovered_plaintext = decrypt_file_bytes(
                cipher_obj,
                recovered_dataset_key,
                manifest.chunks[0].aad.encode('utf-8'),
            )
            if recovered_plaintext is None:
                recovered_sha = None
            else:
                recovered_path.write_bytes(recovered_plaintext)
                recovered_sha = sha256_file(recovered_path)
    else:
        recovered_sha = None
    dataset_decrypt_time = time.time() - decrypt_started

    dataset_recover_success = recovered_sha == plaintext_sha
    audit.add_event(
        'DATASET_RECOVERED',
        dataset_id=dataset_id,
        recovered_path=str(recovered_path),
        recovered_sha256=recovered_sha,
    )
    audit.add_event(
        'VERIFY_SUCCESS' if dataset_recover_success else 'VERIFY_FAILED',
        dataset_id=dataset_id,
        plaintext_sha256=plaintext_sha,
        recovered_sha256=recovered_sha,
    )

    audit_path = output_dir / (dataset_id + '.audit.json')
    audit.save_json(audit_path)

    summary = {
        'dataset_id': dataset_id,
        'dataset_name': dataset_name,
        'domain': domain,
        'source_path': str(dataset_path),
        'dataset_encrypt_success': encrypted_size > 0,
        'dacp_key_recover_success': dacp_key_recover_success,
        'dataset_recover_success': dataset_recover_success,
        'plaintext_sha256': plaintext_sha,
        'recovered_sha256': recovered_sha,
        'manifest_path': str(manifest_path),
        'encrypted_path': str(encrypted_path),
        'recovered_path': str(recovered_path),
        'audit_path': str(audit_path),
        'audit_log_path': str(audit_path),
        'summary_path': str(output_dir / (dataset_id + '.summary.json')),
        'total_time': time.time() - started,
        'dataset_encrypt_time': dataset_encrypt_time,
        'dataset_decrypt_time': dataset_decrypt_time,
        'dacp_encrypt_time': protocol_result.get('dacp_encrypt_time'),
        'csp_transform_time': protocol_result.get('csp_transform_time'),
        'du_final_decrypt_time': protocol_result.get('du_final_decrypt_time'),
        'encrypted_size': encrypted_size,
        'file_size': file_size,
        'num_chunks': len(chunk_records),
        'chunk_mode': bool(chunk_mode),
        'chunk_size': int(chunk_size),
        'policy_str': policy_str,
        'dacp_policy_str': dacp_policy_str,
        'oprf_mode': oprf_mode,
        'sig_mode': sig_mode,
        'symmetric_mode': symmetric_mode,
        'wire_mode': wire_mode,
        'wire_total_bytes': protocol_result['wire_total_bytes'],
        'wire_num_messages': protocol_result['wire_num_messages'],
        'buyer_attrs': buyer_attrs,
        'created_at': manifest.created_at,
        'skipped': False,
        'skip_reason': None,
    }
    summary_path = Path(summary['summary_path'])
    return save_summary_json(summary, summary_path)


def _encrypt_dataset_key_with_dacp(dataset_key, policy_str,
                                   oprf_mode='blind',
                                   sig_mode='ed25519',
                                   wire_mode='json',
                                   buyer_attrs=None):
    group = PairingGroup('MNT224')
    scheme = DACPCPABE(
        group,
        oprf=BlindPairingOPRF(group) if oprf_mode == 'blind' else None,
        signature=Ed25519Signature() if sig_mode == 'ed25519' else None,
        certificate=(
            PrototypeCertificateAuthority(signature=Ed25519Signature())
            if sig_mode == 'ed25519' else None
        ),
        symmetric=AESGCMEnvelope(),
    )
    metrics = ProtocolMetrics()
    wire_codec = WireCodec(group) if wire_mode == 'json' else None
    transport = LocalTransport(
        metrics,
        wire_codec=wire_codec,
        wire_mode=wire_mode == 'json',
    )

    kgc = KGC(scheme, metrics=metrics, transport=transport)
    data_owner = DataOwner(scheme, metrics=metrics, transport=transport)
    csp = CloudServiceProvider(scheme, metrics=metrics, transport=transport)
    du = DataUser(scheme, du_id='DU_DATASET', metrics=metrics, transport=transport)

    pk, _msk = kgc.setup()
    data_owner.set_public_key(pk)
    csp.set_public_key(pk)
    du.set_public_key(pk)

    session_id = new_session_id()
    attrs = list(buyer_attrs) if buyer_attrs is not None else data_owner._policy_attributes(policy_str)
    du.request_user_key(attrs, session_id=session_id)
    kgc.handle_user_key_request(_expect_message(transport, kgc.kgc_id, USER_KEY_REQUEST))
    csp.handle_tk_provision(_expect_message(transport, csp.csp_id, TK_PROVISION))
    du.handle_user_key_response(_expect_message(transport, du.du_id, USER_KEY_RESPONSE))

    if metrics is not None:
        metrics.start_timer('oprf_round_time')
    oprf_msg = data_owner.prepare_oprf_request(policy_str, session_id=session_id)
    kgc.handle_oprf_request(_expect_message(transport, kgc.kgc_id, OPRF_REQUEST))
    data_owner.handle_oprf_response(_expect_message(transport, data_owner.do_id, OPRF_RESPONSE))
    metrics.stop_timer('oprf_round_time')

    require_external_oprf = oprf_mode == 'blind'
    upload_msg = data_owner.encrypt_and_upload(
        dataset_key,
        policy_str,
        session_id=session_id,
        batch_id=oprf_msg.payload['batch_id'],
        require_external_oprf=require_external_oprf,
    )
    csp.store_ciphertext(_expect_message(transport, csp.csp_id, CIPHERTEXT_UPLOAD))

    ct_id = upload_msg.payload['ct_id']
    du.request_access(ct_id, session_id=session_id)
    csp.handle_access_request(_expect_message(transport, csp.csp_id, ACCESS_REQUEST))
    recovered_dataset_key = du.handle_transform_response(
        _expect_message(transport, du.du_id, TRANSFORM_RESPONSE)
    )
    summary = metrics.summary()
    return {
        'recovered_dataset_key': recovered_dataset_key,
        'ct_id': ct_id,
        'external_oprf_tokens_used': upload_msg.payload['external_oprf_tokens_used'],
        'matched_candidates': du.last_verification_stats.get('row_signatures_verified', 0),
        'wire_total_bytes': summary['wire_total_bytes'],
        'wire_num_messages': summary['wire_num_messages'],
        'dacp_encrypt_time': summary['do_encrypt_time'],
        'csp_transform_time': summary['csp_transform_time'],
        'du_final_decrypt_time': summary['du_final_decrypt_time'],
    }


def _expect_message(transport, receiver, msg_type):
    msg = transport.receive_one(receiver, msg_type)
    if msg is None:
        raise RuntimeError('missing {0} for {1}'.format(msg_type, receiver))
    return msg
