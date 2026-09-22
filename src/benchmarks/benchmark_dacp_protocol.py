'''
Coarse protocol-level DACP benchmark.
'''

import sys
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, GT

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


def expect_message(transport, receiver, msg_type):
    msg = transport.receive_one(receiver, msg_type)
    if msg is None:
        raise RuntimeError('missing {0} for {1}'.format(msg_type, receiver))
    return msg


def make_or_policy(n):
    attrs = [str(i) for i in range(1, n + 1)]
    # Protocol benchmark focuses on message flow and role costs. The current
    # algorithm-level DACP prototype searches reconstruction subsets
    # combinatorially, so a 50-way AND policy would benchmark that search
    # limitation rather than the protocol. OR keeps policy_rows=n while making
    # reconstruction fast and deterministic.
    policy = '(' + ' OR '.join(attrs) + ')'
    return attrs, policy


def make_scheme(group, oprf_mode, sig_mode, symmetric_mode):
    kwargs = {}
    if oprf_mode == 'blind':
        kwargs['oprf'] = BlindPairingOPRF(group)
    if sig_mode == 'ed25519':
        kwargs['signature'] = Ed25519Signature()
        kwargs['certificate'] = PrototypeCertificateAuthority(signature=Ed25519Signature())
    if symmetric_mode == 'aesgcm':
        kwargs['symmetric'] = AESGCMEnvelope()
    return DACPCPABE(group, **kwargs)


def make_plaintext(group, symmetric_mode):
    if symmetric_mode == 'aesgcm':
        return b'hello dacp secure data sharing'
    return group.random(GT)


def run_case(case_name, num_attrs, oprf_mode, sig_mode, symmetric_mode, wire_mode):
    metrics = ProtocolMetrics()
    group = PairingGroup('MNT224')
    wire_codec = WireCodec(group) if wire_mode == 'json' else None
    transport = LocalTransport(
        metrics,
        wire_codec=wire_codec,
        wire_mode=wire_mode == 'json',
    )
    scheme = make_scheme(group, oprf_mode, sig_mode, symmetric_mode)

    kgc = KGC(scheme, metrics=metrics, transport=transport)
    data_owner = DataOwner(scheme, metrics=metrics, transport=transport)
    csp = CloudServiceProvider(scheme, metrics=metrics, transport=transport)
    du = DataUser(scheme, du_id='DU_' + case_name.upper(), metrics=metrics, transport=transport)

    metrics.start_timer('end_to_end_time')
    pk, _msk = kgc.setup()
    data_owner.set_public_key(pk)
    csp.set_public_key(pk)
    du.set_public_key(pk)

    attr_list, policy_str = make_or_policy(num_attrs)
    msg = make_plaintext(group, symmetric_mode)
    session_id = new_session_id()

    du.request_user_key(attr_list, session_id=session_id)
    kgc.handle_user_key_request(expect_message(transport, kgc.kgc_id, USER_KEY_REQUEST))
    csp.handle_tk_provision(expect_message(transport, csp.csp_id, TK_PROVISION))
    du.handle_user_key_response(expect_message(transport, du.du_id, USER_KEY_RESPONSE))

    metrics.start_timer('oprf_round_time')
    oprf_msg = data_owner.prepare_oprf_request(policy_str, session_id=session_id)
    kgc.handle_oprf_request(expect_message(transport, kgc.kgc_id, OPRF_REQUEST))
    data_owner.handle_oprf_response(expect_message(transport, data_owner.do_id, OPRF_RESPONSE))
    metrics.stop_timer('oprf_round_time')

    require_external_oprf = oprf_mode == 'blind'
    upload_msg = data_owner.encrypt_and_upload(
        msg,
        policy_str,
        session_id=session_id,
        batch_id=oprf_msg.payload['batch_id'],
        require_external_oprf=require_external_oprf,
    )
    csp.store_ciphertext(expect_message(transport, csp.csp_id, CIPHERTEXT_UPLOAD))
    ct_id = upload_msg.payload['ct_id']
    policy_rows = len(upload_msg.payload['ctxt']['A_star'])

    du.request_access(ct_id, session_id=session_id)
    csp.handle_access_request(expect_message(transport, csp.csp_id, ACCESS_REQUEST))
    recovered = du.handle_transform_response(expect_message(transport, du.du_id, TRANSFORM_RESPONSE))
    metrics.stop_timer('end_to_end_time')

    summary = metrics.summary()
    return {
        'case_name': case_name,
        'oprf_mode': oprf_mode,
        'signature_mode': sig_mode,
        'symmetric_mode': symmetric_mode,
        'wire_mode': wire_mode,
        'num_attrs': num_attrs,
        'policy_rows': policy_rows,
        'setup_time': summary['setup_time'],
        'user_key_time': summary['user_key_time'],
        'oprf_round_time': summary['oprf_round_time'],
        'do_encrypt_time': summary['do_encrypt_time'],
        'ciphertext_upload_bytes': summary['ciphertext_upload_bytes'],
        'tk_provision_bytes': summary['tk_provision_bytes'],
        'access_request_bytes': summary['access_request_bytes'],
        'csp_transform_time': summary['csp_transform_time'],
        'transform_response_bytes': summary['transform_response_bytes'],
        'du_final_decrypt_time': summary['du_final_decrypt_time'],
        'end_to_end_time': summary['end_to_end_time'],
        'total_protocol_bytes': summary['total_protocol_bytes'],
        'wire_total_bytes': summary['wire_total_bytes'],
        'wire_num_messages': summary['wire_num_messages'],
        'wire_avg_message_bytes': (
            float(summary['wire_total_bytes']) / summary['wire_num_messages']
            if summary['wire_num_messages'] else 0.0
        ),
        'oprf_request_wire_bytes': summary['oprf_request_wire_bytes'],
        'oprf_response_wire_bytes': summary['oprf_response_wire_bytes'],
        'ciphertext_upload_wire_bytes': summary['ciphertext_upload_wire_bytes'],
        'tk_provision_wire_bytes': summary['tk_provision_wire_bytes'],
        'access_request_wire_bytes': summary['access_request_wire_bytes'],
        'transform_response_wire_bytes': summary['transform_response_wire_bytes'],
        'external_oprf_tokens_used': upload_msg.payload['external_oprf_tokens_used'],
        'num_external_oprf_tokens': summary['num_external_oprf_tokens'],
        'cert_verified': du.last_verification_stats.get('cert_verified', False),
        'row_signatures_verified': du.last_verification_stats.get('row_signatures_verified', 0),
        'aead_authenticated': du.last_verification_stats.get('aead_authenticated', False),
        'bytes_plaintext_success': symmetric_mode == 'aesgcm' and recovered == msg,
        'success': recovered == msg,
    }


def fmt_time(value):
    return '{0:.3f}'.format(value * 1000.0)


def main():
    parser = argparse.ArgumentParser(description='Run DACP protocol benchmark.')
    parser.add_argument('--oprf', choices=('prototype', 'blind'), default='prototype')
    parser.add_argument('--sig', choices=('prototype', 'ed25519'), default='prototype')
    parser.add_argument('--symmetric', choices=('gt', 'aesgcm'), default='gt')
    parser.add_argument('--wire', choices=('none', 'json'), default='none')
    args = parser.parse_args()

    cases = [
        ('small', 5),
        ('medium', 20),
        ('large', 50),
    ]
    rows = [
        run_case(name, count, args.oprf, args.sig, args.symmetric, args.wire)
        for name, count in cases
    ]

    headers = [
        'case_name',
        'signature_mode',
        'symmetric_mode',
        'wire_mode',
        'num_attrs',
        'policy_rows',
        'setup_time',
        'user_key_time',
        'oprf_round_time',
        'do_encrypt_time',
        'ciphertext_upload_bytes',
        'tk_provision_bytes',
        'access_request_bytes',
        'csp_transform_time',
        'transform_response_bytes',
        'du_final_decrypt_time',
        'end_to_end_time',
        'total_protocol_bytes',
        'wire_total_bytes',
        'wire_num_messages',
        'wire_avg_message_bytes',
        'oprf_request_wire_bytes',
        'oprf_response_wire_bytes',
        'ciphertext_upload_wire_bytes',
        'tk_provision_wire_bytes',
        'access_request_wire_bytes',
        'transform_response_wire_bytes',
        'external_oprf_tokens_used',
        'num_external_oprf_tokens',
        'cert_verified',
        'row_signatures_verified',
        'aead_authenticated',
        'bytes_plaintext_success',
        'success',
    ]

    print('DACP protocol benchmark')
    print('=' * 250)
    print('oprf_mode: {0}'.format(args.oprf))
    print('signature_mode: {0}'.format(args.sig))
    print('symmetric_mode: {0}'.format(args.symmetric))
    print('wire_mode: {0}'.format(args.wire))
    print('{:<10} {:>14} {:>14} {:>9} {:>9} {:>11} {:>11} {:>13} {:>15} {:>13} {:>23} {:>18} {:>20} {:>18} {:>24} {:>20} {:>15} {:>22} {:>16} {:>17} {:>22} {:>23} {:>23} {:>28} {:>23} {:>25} {:>29} {:>25} {:>24} {:>13} {:>23} {:>18} {:>23} {:>9}'.format(*headers))
    for row in rows:
        print('{:<10} {:>14} {:>14} {:>9} {:>9} {:>11} {:>11} {:>13} {:>15} {:>13} {:>23} {:>18} {:>20} {:>18} {:>24} {:>20} {:>15} {:>22} {:>16} {:>17} {:>22.1f} {:>23} {:>23} {:>28} {:>23} {:>25} {:>29} {:>25} {:>24} {:>13} {:>23} {:>18} {:>23} {:>9}'.format(
            row['case_name'],
            row['signature_mode'],
            row['symmetric_mode'],
            row['wire_mode'],
            row['num_attrs'],
            row['policy_rows'],
            fmt_time(row['setup_time']),
            fmt_time(row['user_key_time']),
            fmt_time(row['oprf_round_time']),
            fmt_time(row['do_encrypt_time']),
            row['ciphertext_upload_bytes'],
            row['tk_provision_bytes'],
            row['access_request_bytes'],
            fmt_time(row['csp_transform_time']),
            row['transform_response_bytes'],
            fmt_time(row['du_final_decrypt_time']),
            fmt_time(row['end_to_end_time']),
            row['total_protocol_bytes'],
            row['wire_total_bytes'],
            row['wire_num_messages'],
            row['wire_avg_message_bytes'],
            row['oprf_request_wire_bytes'],
            row['oprf_response_wire_bytes'],
            row['ciphertext_upload_wire_bytes'],
            row['tk_provision_wire_bytes'],
            row['access_request_wire_bytes'],
            row['transform_response_wire_bytes'],
            row['external_oprf_tokens_used'],
            row['num_external_oprf_tokens'],
            row['cert_verified'],
            row['row_signatures_verified'],
            row['aead_authenticated'],
            row['bytes_plaintext_success'],
            row['success'],
        ))
    print()
    if args.wire == 'json':
        print('Time columns are milliseconds. Byte columns use JSON wire encoded lengths.')
    else:
        print('Time columns are milliseconds. Byte columns are coarse local serialization estimates.')


if __name__ == "__main__":
    main()
