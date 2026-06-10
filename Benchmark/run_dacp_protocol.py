'''
End-to-end local DACP protocol simulation.
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


def provision_user(du, kgc, transport, attr_list, session_id):
    du.request_user_key(attr_list, session_id=session_id)
    kgc.handle_user_key_request(expect_message(transport, kgc.kgc_id, USER_KEY_REQUEST))
    tk_msg = expect_message(transport, 'CSP', TK_PROVISION)
    return_tk_receiver = tk_msg.receiver
    du.handle_user_key_response(expect_message(transport, du.du_id, USER_KEY_RESPONSE))
    return tk_msg, return_tk_receiver


def do_oprf_round(data_owner, kgc, transport, policy_str, session_id):
    if data_owner.metrics is not None:
        data_owner.metrics.start_timer('oprf_round_time')
    oprf_msg = data_owner.prepare_oprf_request(policy_str, session_id=session_id)
    kgc.handle_oprf_request(expect_message(transport, kgc.kgc_id, OPRF_REQUEST))
    data_owner.handle_oprf_response(expect_message(transport, data_owner.do_id, OPRF_RESPONSE))
    if data_owner.metrics is not None:
        data_owner.metrics.stop_timer('oprf_round_time')
    return oprf_msg.payload['batch_id']


def upload_ciphertext(data_owner, csp, transport, msg, policy_str, session_id,
                      batch_id=None, require_external_oprf=False):
    upload_msg = data_owner.encrypt_and_upload(
        msg,
        policy_str,
        session_id=session_id,
        batch_id=batch_id,
        require_external_oprf=require_external_oprf,
    )
    csp.store_ciphertext(expect_message(transport, csp.csp_id, CIPHERTEXT_UPLOAD))
    return upload_msg.payload['ct_id'], upload_msg.payload['external_oprf_tokens_used']


def access_ciphertext(du, csp, transport, ct_id, session_id):
    du.request_access(ct_id, session_id=session_id)
    csp.handle_access_request(expect_message(transport, csp.csp_id, ACCESS_REQUEST))
    return du.handle_transform_response(expect_message(transport, du.du_id, TRANSFORM_RESPONSE))


def print_message_log(transport):
    print('Protocol Message Log')
    print('-' * 112)
    print('{:<4} {:<22} {:<10} {:<10} {:>5} {:>8} {:>8} {:>12} {:>12}'.format(
        '#', 'type', 'sender', 'receiver', 'seq', 'replay', 'expired', 'bytes', 'wire_bytes'
    ))
    for index, item in enumerate(transport.log, 1):
        print('{:<4} {:<22} {:<10} {:<10} {:>5} {:>8} {:>8} {:>12} {:>12}'.format(
            index,
            item['msg_type'],
            item['sender'],
            item['receiver'],
            item['seq'],
            str(item['replayed']),
            str(item['expired']),
            item['bytes'],
            item.get('wire_bytes', 0),
        ))


def make_scheme(group, oprf_mode, sig_mode, symmetric_mode):
    kwargs = {}
    if oprf_mode == 'blind':
        kwargs['oprf'] = BlindPairingOPRF(group)
    if sig_mode == 'ed25519':
        row_signature = Ed25519Signature()
        ca_signature = Ed25519Signature()
        kwargs['signature'] = row_signature
        kwargs['certificate'] = PrototypeCertificateAuthority(signature=ca_signature)
    if symmetric_mode == 'aesgcm':
        kwargs['symmetric'] = AESGCMEnvelope()
    return DACPCPABE(group, **kwargs)


def make_plaintext(group, symmetric_mode):
    if symmetric_mode == 'aesgcm':
        return b'hello dacp secure data sharing'
    return group.random(GT)


def main():
    parser = argparse.ArgumentParser(description='Run local DACP protocol simulation.')
    parser.add_argument('--oprf', choices=('prototype', 'blind'), default='prototype')
    parser.add_argument('--sig', choices=('prototype', 'ed25519'), default='prototype')
    parser.add_argument('--symmetric', choices=('gt', 'aesgcm'), default='gt')
    parser.add_argument('--wire', choices=('none', 'json'), default='none')
    args = parser.parse_args()

    metrics = ProtocolMetrics()
    group = PairingGroup('MNT224')
    wire_codec = WireCodec(group) if args.wire == 'json' else None
    transport = LocalTransport(
        metrics,
        wire_codec=wire_codec,
        wire_mode=args.wire == 'json',
    )
    scheme = make_scheme(group, args.oprf, args.sig, args.symmetric)

    kgc = KGC(scheme, metrics=metrics, transport=transport)
    data_owner = DataOwner(scheme, metrics=metrics, transport=transport)
    csp = CloudServiceProvider(scheme, metrics=metrics, transport=transport)
    du_good = DataUser(scheme, du_id='DU_GOOD', metrics=metrics, transport=transport)
    du_bad = DataUser(scheme, du_id='DU_BAD', metrics=metrics, transport=transport)

    metrics.start_timer('end_to_end_time')
    pk, _msk = kgc.setup()
    data_owner.set_public_key(pk)
    csp.set_public_key(pk)
    du_good.set_public_key(pk)
    du_bad.set_public_key(pk)

    policy_str = '((1 and 3) and (2 OR 4))'
    msg = make_plaintext(group, args.symmetric)
    session_id = new_session_id()

    tk_msg, _ = provision_user(du_good, kgc, transport, ['1', '2', '3'], session_id)
    csp.handle_tk_provision(tk_msg)
    batch_id = do_oprf_round(data_owner, kgc, transport, policy_str, session_id)
    require_external_oprf = args.oprf == 'blind'
    ct_id, external_used = upload_ciphertext(
        data_owner,
        csp,
        transport,
        msg,
        policy_str,
        session_id,
        batch_id=batch_id,
        require_external_oprf=require_external_oprf,
    )
    recovered = access_ciphertext(du_good, csp, transport, ct_id, session_id)

    bad_session_id = new_session_id()
    bad_tk_msg, _ = provision_user(du_bad, kgc, transport, ['1', '4'], bad_session_id)
    csp.handle_tk_provision(bad_tk_msg)
    failed = access_ciphertext(du_bad, csp, transport, ct_id, bad_session_id)
    metrics.stop_timer('end_to_end_time')

    print('DACP protocol simulation')
    print('=' * 92)
    print('oprf_mode: {0}'.format(args.oprf))
    print('signature_mode: {0}'.format(args.sig))
    print('symmetric_mode: {0}'.format(args.symmetric))
    print('wire_mode: {0}'.format(args.wire))
    print('external_oprf_tokens_used: {0}'.format(external_used))
    print('OPRF tokens are used by encrypt: {0}'.format(external_used))
    print('cert_verified: {0}'.format(
        du_good.last_verification_stats.get('cert_verified', False)
    ))
    print('row_signatures_verified: {0}'.format(
        du_good.last_verification_stats.get('row_signatures_verified', 0)
    ))
    print('aead_authenticated: {0}'.format(
        du_good.last_verification_stats.get('aead_authenticated', False)
    ))
    print('bytes_plaintext_success: {0}'.format(
        args.symmetric == 'aesgcm' and recovered == msg
    ))
    print('satisfied_success: {0}'.format(recovered == msg))
    print('unsatisfied_returns_none: {0}'.format(failed is None))
    print('ct_id: {0}'.format(ct_id))
    print('good_tk_entries_at_csp: {0}'.format(
        len(csp.user_transform_keys['DU_GOOD']['attributes'])
    ))
    print('bad_tk_entries_at_csp: {0}'.format(
        len(csp.user_transform_keys['DU_BAD']['attributes'])
    ))
    print('csp_has_user_transform_keys: {0}'.format(sorted(csp.user_transform_keys.keys())))
    summary = metrics.summary()
    print('wire_total_bytes: {0}'.format(summary['wire_total_bytes']))
    print('wire_num_messages: {0}'.format(summary['wire_num_messages']))
    print()
    print_message_log(transport)
    print()
    metrics.print_summary()


if __name__ == "__main__":
    main()
