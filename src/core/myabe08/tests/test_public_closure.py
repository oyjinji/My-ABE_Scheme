"""Deterministic public-boundary closure checks using real generated TEST objects."""
import ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct

import pytest

import core.myabe08 as package
from core.myabe08.crypto import compute_ctx_priv
from core.myabe08.encoding import UInt32, decode, encode
from core.myabe08.errors import MyABE08Error
from core.myabe08.profile import EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1
from core.myabe08.public import (EMULATED_TEST_MODE, PublicMyABE08,
    parse_authorization, parse_ciphertext, parse_partial,
    serialize_authorization, serialize_ciphertext, serialize_partial)
from core.myabe08.signing import new_private_key, public_key_bytes
from core.myabe08.revocation import REVOKE
from core.myabe08.types import Attribute, PolicyContext, PolicyInput, Validity

SYS_ID = b'MYABE08-4EFR-CLOSURE'
CANARY_UID = 'PRIVATE-UID-4EFR-91e58e183d564fd7'
CANARY_ATTRIBUTE = 'PRIVATE-ATTRIBUTE-4EFR-4a8a44a1'


class Clock:
    def now(self): return 1000


@pytest.fixture
def public_objects(tmp_path):
    scheme = PublicMyABE08(sys_id=SYS_ID, namespace='private-namespace',
        backend=EMULATED_TEE_PROFILE, experiment_trust_mode=EMULATED_TEST_MODE,
        state_path=tmp_path/'state', clock=Clock())
    scheme.Setup(c_max=3, validity=Validity(100, 2000))
    holder = new_private_key()
    label = Attribute('private-namespace', 'label', CANARY_ATTRIBUTE)
    user = scheme.KeyGen(uid=CANARY_UID, attributes=(label,),
        auth_public_key=public_key_bytes(holder), validity=Validity(100, 2000))
    context_id = b'C'*32
    context = PolicyContext(SYS_ID, context_id, 1,
                            compute_ctx_priv(SYS_ID, context_id, 1))
    ct = scheme.Encrypt(message=b'closure-message',
        policy=PolicyInput(((1,),), (label,)), context=context, data_id=b'closure')
    auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
                               auth_private_key=holder, expiry=1500)
    return scheme, user, holder, ct, auth


def _flip(raw):
    return raw[:-1] + bytes((raw[-1] ^ 1,))


def _wire_mutate(raw, index, value):
    record = list(decode(raw)); record[index] = value
    return encode(tuple(record))


def test_supported_root_facade_and_ast_gate():
    assert package.PublicMyABE08 is PublicMyABE08
    assert 'MyABE08' not in package.__all__
    assert not hasattr(package, 'MyABE08')
    source = Path(__file__).resolve().parents[1]
    tree = ast.parse((source/'public.py').read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'PublicMyABE08')
    methods = {n.name: n for n in cls.body if isinstance(n, ast.FunctionDef)}
    names = ('Setup','KeyGen','Encrypt','Rev','RevStateUpt','TEEAuthorize','Transform','FinalDec')
    assert all(name in methods for name in names)
    for name in names:
        body = ast.get_source_segment((source/'public.py').read_text(), methods[name])
        assert not any(token in body for token in ('NotImplemented', 'TODO', 'FIXME', 'mock_', 'unimplemented('))
    forbidden = ('fxabe_05_3_exp', 'fxabe_rev', 'fxdacp', 'fabeo22cp', 'fabesa')
    for path in source.rglob('*.py'):
        if 'tests' in path.parts or path.name in ('legacy.py','scheme.py'):
            continue
        parsed = ast.parse(path.read_text())
        imports = [node.module or '' for node in ast.walk(parsed)
                   if isinstance(node, ast.ImportFrom)]
        imports += [alias.name for node in ast.walk(parsed) if isinstance(node, ast.Import)
                    for alias in node.names]
        assert all(not any(item in module for item in forbidden) for module in imports)


def test_canonical_roundtrip_and_negative_corpus(public_objects):
    scheme, _, _, ct, auth = public_objects
    partial = scheme.Transform(ciphertext=ct, public_auth=auth)
    backend = scheme.crypto
    ct_wire = serialize_ciphertext(ct, backend)
    auth_wire = serialize_authorization(auth, ct, backend)
    partial_wire = serialize_partial(partial, backend)
    assert serialize_ciphertext(parse_ciphertext(ct_wire, backend,
        expected_profile=EMULATED_TEE_PROFILE), backend) == ct_wire
    assert serialize_authorization(parse_authorization(auth_wire, ct, backend,
        expected_profile=EMULATED_TEE_PROFILE), ct, backend) == auth_wire
    assert serialize_partial(parse_partial(partial_wire, backend,
        expected_profile=EMULATED_TEE_PROFILE), backend) == partial_wire
    for parser, wire in ((parse_ciphertext,ct_wire), (parse_authorization,auth_wire),
                         (parse_partial,partial_wire)):
        args = (ct, backend) if parser is parse_authorization else (backend,)
        for damaged in (b'', wire[:-1], wire[:len(wire)//3],
                        wire[:len(wire)//2], wire[:2*len(wire)//3],
                        wire + b'\x00', b'\xff'+wire[1:],
                        wire[:1]+b'\xff\xff\xff\xff'+wire[5:]):
            with pytest.raises(MyABE08Error):
                parser(damaged, *args, expected_profile=EMULATED_TEE_PROFILE)
        with pytest.raises(MyABE08Error):
            parser(wire, *args, expected_profile=SGX_DEBUG_GRAMINE_V1)
        with pytest.raises(MyABE08Error):
            parser(wire, *(ct, type(backend)(b'wrong-system') ) if parser is parse_authorization
                   else (type(backend)(b'wrong-system'),),
                   expected_profile=EMULATED_TEE_PROFILE)
    for parser, wire in ((parse_ciphertext,ct_wire), (parse_authorization,auth_wire),
                         (parse_partial,partial_wire)):
        args = (ct,backend) if parser is parse_authorization else (backend,)
        for index, value in ((0,'WRONG-VERSION'), (1,SGX_DEBUG_GRAMINE_V1)):
            with pytest.raises(MyABE08Error):
                parser(_wire_mutate(wire,index,value), *args,
                       expected_profile=EMULATED_TEE_PROFILE)
    # The CT inner codec checks group decoding and fixed-width scalar range.
    wrapper = decode(ct_wire); inner = list(decode(wrapper[3]))
    header = list(inner[5]); header[1] = b'\xff'*48
    inner[5] = tuple(header)
    with pytest.raises(MyABE08Error):
        parse_ciphertext(_wire_mutate(ct_wire,3,encode(tuple(inner))), backend,
                         expected_profile=EMULATED_TEE_PROFILE)
    inner = list(decode(wrapper[3])); header = list(inner[5]); header[1] = b'\x00'*96
    inner[5] = tuple(header)
    with pytest.raises(MyABE08Error):
        parse_ciphertext(_wire_mutate(ct_wire,3,encode(tuple(inner))), backend,
                         expected_profile=EMULATED_TEE_PROFILE)
    inner = list(decode(wrapper[3])); matrix = list(inner[8]); matrix[0] = (b'\xff'*32,)
    inner[8] = tuple(matrix)
    with pytest.raises(MyABE08Error):
        parse_ciphertext(_wire_mutate(ct_wire,3,encode(tuple(inner))), backend,
                         expected_profile=EMULATED_TEE_PROFILE)
    inner = list(decode(wrapper[3])); components = list(inner[7]); components[0] = b'\xff'*96
    inner[7] = tuple(components)
    with pytest.raises(MyABE08Error):
        parse_ciphertext(_wire_mutate(ct_wire,3,encode(tuple(inner))), backend,
                         expected_profile=EMULATED_TEE_PROFILE)
    with pytest.raises(MyABE08Error):
        parse_partial(_wire_mutate(partial_wire,4,b'\xff'*576), backend,
                      expected_profile=EMULATED_TEE_PROFILE)
    with pytest.raises(MyABE08Error):
        parse_ciphertext(_wire_mutate(ct_wire,3,encode(tuple(
            list(decode(wrapper[3]))[:7] + [(b'\x00'*96,)*3]
            + list(decode(wrapper[3]))[8:]))), backend,
            expected_profile=EMULATED_TEE_PROFILE)
    with pytest.raises(MyABE08Error):
        parse_partial(_wire_mutate(partial_wire,8,UInt32(0)), backend,
                      expected_profile=EMULATED_TEE_PROFILE)
    auth_value = list(decode(auth_wire)); envelope = list(decode(auth_value[4]))
    bundle = list(decode(envelope[1])); bundle[2] = b'\xff'*96
    envelope[1] = encode(tuple(bundle)); auth_value[4] = encode(tuple(envelope))
    with pytest.raises(MyABE08Error):
        parse_authorization(encode(tuple(auth_value)), ct, backend,
                            expected_profile=EMULATED_TEE_PROFILE)
    # Ordered tuple schemas reject missing and unexpected fields.
    for wire, parser, args in ((ct_wire,parse_ciphertext,(backend,)),
                               (auth_wire,parse_authorization,(ct,backend)),
                               (partial_wire,parse_partial,(backend,))):
        fields = decode(wire)
        for altered in (fields[:-1], fields+(b'extra',), list(fields)):
            with pytest.raises(MyABE08Error):
                parser(encode(altered), *args, expected_profile=EMULATED_TEE_PROFILE)
    # The common framed decoder rejects duplicate named fields, including
    # when a hand-crafted stream bypasses StructuredRecord construction.
    payload = struct.pack('>I',2) + encode('R') + encode('a') + encode(b'x')
    payload += encode('a') + encode(b'y')
    with pytest.raises(MyABE08Error):
        decode(bytes((8,))+struct.pack('>I',len(payload))+payload)


PUBLIC_TAMPER_MATRIX = (
    ('CT.header', 'header', lambda ct, auth: replace(ct, header=replace(ct.header, data_id=b'changed'))),
    ('CT.C', 'C', lambda ct, auth: replace(ct, header=replace(ct.header,
        c=replace(ct.header.c, encoded=_flip(ct.header.c.encoded))))),
    ('CT.C_i', 'C_i', lambda ct, auth: replace(ct, row_components=(replace(ct.row_components[0],
        encoded=_flip(ct.row_components[0].encoded)),))),
    ('CT.D_j', 'D_j', lambda ct, auth: replace(ct, occurrence_components=(
        replace(ct.occurrence_components[0], encoded=_flip(ct.occurrence_components[0].encoded)),)
        + ct.occurrence_components[1:])),
    ('CT.AF_slot', 'AF slot bytes', lambda ct, auth: replace(ct, anonymous_filter=replace(
        ct.anonymous_filter, slots=(_flip(ct.anonymous_filter.slots[0]),)
        + ct.anonymous_filter.slots[1:]))),
    ('CT.AF_metadata', 'AF metadata', lambda ct, auth: replace(ct, anonymous_filter=replace(
        ct.anonymous_filter, metadata=replace(ct.anonymous_filter.metadata,
        seed_af=_flip(ct.anonymous_filter.metadata.seed_af))))),
    ('CT.AF_header_binding', 'AF/header binding', lambda ct, auth: replace(ct,
        header=replace(ct.header, af_header=replace(ct.header.af_header,
        matrix_digest=b'M'*32)))),
    ('CT.core_digest', 'core components digest', lambda ct, auth: replace(ct,
        header=replace(ct.header, core_components_digest=b'C'*32))),
    ('CT.filter_digest', 'filter digest', lambda ct, auth: replace(ct,
        header=replace(ct.header, filter_digest=b'F'*32))),
    ('CT.matrix', 'matrix', lambda ct, auth: replace(ct,
        matrix=((2,),))),
    ('CT.policy_context_id', 'PolicyContextID', lambda ct, auth: replace(ct,
        header=replace(ct.header, context=replace(ct.header.context,
        policy_context_id=b'P'*32)))),
    ('CT.policy_version', 'PolicyVersion', lambda ct, auth: replace(ct,
        header=replace(ct.header, context=replace(ct.header.context,
        policy_version=ct.header.context.policy_version+1)))),
    ('CT.publisher_certificate', 'publication payload', lambda ct, auth: replace(ct,
        publisher_certificate=replace(ct.publisher_certificate,
        kgc_signature=_flip(ct.publisher_certificate.kgc_signature)))),
    ('CT.n_DEM', 'n_DEM', lambda ct, auth: replace(ct, dem_nonce=_flip(ct.dem_nonce))),
    ('CT.C_sym', 'C_sym', lambda ct, auth: replace(ct, encrypted_message=_flip(ct.encrypted_message))),
    ('CT.publication_signature', 'publication signature', lambda ct, auth: replace(
        ct, publication_signature=_flip(ct.publication_signature))),
)


def test_public_tamper_matrix_machine_readable(public_objects, tmp_path):
    scheme, user, holder, ct, auth = public_objects
    cases = []
    dynamic = tuple((f'CT.C_i[{i}]', 'C_i',
        lambda ct, auth, i=i: replace(ct, row_components=ct.row_components[:i]
            + (replace(ct.row_components[i], encoded=_flip(ct.row_components[i].encoded)),)
            + ct.row_components[i+1:])) for i in range(len(ct.row_components)))
    dynamic += tuple((f'CT.D_j[{i}]', 'D_j',
        lambda ct, auth, i=i: replace(ct, occurrence_components=ct.occurrence_components[:i]
            + (replace(ct.occurrence_components[i],
                encoded=_flip(ct.occurrence_components[i].encoded)),)
            + ct.occurrence_components[i+1:])) for i in range(len(ct.occurrence_components)))
    dynamic += tuple((f'CT.AF_slot[{i}]', 'AF slot bytes',
        lambda ct, auth, i=i: replace(ct, anonymous_filter=replace(ct.anonymous_filter,
            slots=ct.anonymous_filter.slots[:i] + (_flip(ct.anonymous_filter.slots[i]),)
            + ct.anonymous_filter.slots[i+1:])))
        for i in range(len(ct.anonymous_filter.slots)))
    for case_id, field, change in PUBLIC_TAMPER_MATRIX + dynamic:
        changed = change(ct, auth)
        try:
            scheme.Transform(ciphertext=changed, public_auth=auth)
        except MyABE08Error as exc:
            cases.append(dict(case_id=case_id, object='CT', field=field,
                expected_result='REJECT', actual_result='REJECT', error_class=type(exc).__name__))
        else:
            pytest.fail(case_id + ' accepted')
    # Fresh Auths avoid confusing one-time consumption with tamper rejection.
    fresh = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                auth_private_key=holder, expiry=1500)
    raw, bundle = fresh.authorization, fresh.authorization.bundle
    cap = raw.capability
    auth_cases = (
        ('Auth.Bq', replace(raw, bundle=replace(bundle, items=(replace(bundle.items[0],
            token=_flip(bundle.items[0].token)),) + bundle.items[1:]))),
        ('Auth.K1q', replace(raw, bundle=replace(bundle, k1_q=replace(bundle.k1_q,
            encoded=_flip(bundle.k1_q.encoded))))),
        ('Auth.K_tau_q', replace(raw, bundle=replace(bundle, items=(replace(bundle.items[0],
            k_tau_q=replace(bundle.items[0].k_tau_q,
                encoded=_flip(bundle.items[0].k_tau_q.encoded))),) + bundle.items[1:]))),
        ('Auth.T0q', replace(raw, bundle=replace(bundle, t0_q=replace(bundle.t0_q,
            encoded=_flip(bundle.t0_q.encoded))))),
        ('Auth.rev_version', replace(raw, capability=replace(cap, rev_version=cap.rev_version+1))),
        ('Auth.request_nonce', replace(raw, capability=replace(cap, request_nonce=b'R'*32))),
        ('Auth.expiry', replace(raw, capability=replace(cap, expiry=cap.expiry+1))),
        ('Auth.capq', replace(raw, capability=replace(cap, signature=_flip(cap.signature)))),
        ('Auth.cap_digest', replace(raw, capability=replace(cap, bundle_digest=b'D'*32))),
    )
    for case_id, changed in auth_cases:
        try:
            scheme.Transform(ciphertext=ct, public_auth=replace(fresh, authorization=changed))
        except MyABE08Error as exc:
            cases.append(dict(case_id=case_id, object='Auth', field=case_id.split('.')[1],
                expected_result='REJECT', actual_result='REJECT', error_class=type(exc).__name__))
        else:
            pytest.fail(case_id + ' accepted')
    assert scheme.FinalDec(partial=scheme.Transform(ciphertext=ct, public_auth=fresh),
                           recovery_key=user.recovery_key) == b'closure-message'
    # E is not published as a CT field in MYABE-08. A changed reconstructed
    # E_hat (via T_A) must fail DEM authentication, never release plaintext.
    later_auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
                                    auth_private_key=holder, expiry=1500)
    changed_partial = replace(scheme.Transform(ciphertext=ct,
        public_auth=later_auth), t_a=later_auth.authorization.bundle.t0_q)
    with pytest.raises(MyABE08Error):
        scheme.FinalDec(partial=changed_partial, recovery_key=user.recovery_key)
    path = tmp_path/'PUBLIC_TAMPER_MATRIX.json'
    path.write_text(json.dumps(cases, sort_keys=True))
    assert len(json.loads(path.read_text())) == len(PUBLIC_TAMPER_MATRIX)+len(dynamic)+len(auth_cases)
    assert CANARY_UID not in path.read_text() and CANARY_ATTRIBUTE not in path.read_text()


def test_mixing_replay_and_wrong_recovery_key(public_objects, tmp_path):
    scheme, user, holder, ct_a, auth_a = public_objects
    label = Attribute('private-namespace', 'label', CANARY_ATTRIBUTE)
    context_id = b'B'*32
    ctx_b = PolicyContext(SYS_ID, context_id, 2,
                          compute_ctx_priv(SYS_ID, context_id, 2))
    ct_b = scheme.Encrypt(message=b'other-request', policy=PolicyInput(((1,),), (label,)),
        context=ctx_b, data_id=b'other-request')
    auth_b = scheme.TEEAuthorize(user=user, ciphertext=ct_b,
                                 auth_private_key=holder, expiry=1500)
    other_holder = new_private_key()
    other = scheme.KeyGen(uid='PRIVATE-OTHER-USER-4EFR', attributes=(label,),
        auth_public_key=public_key_bytes(other_holder), validity=Validity(100, 2000))
    auth_other = scheme.TEEAuthorize(user=other, ciphertext=ct_a,
                                     auth_private_key=other_holder, expiry=1500)
    mixing = (
        ('CT_A+Auth_B', ct_a, auth_b),
        ('CT_B+Auth_A', ct_b, auth_a),
        ('request_A+cap_B', ct_a, replace(auth_a,
            authorization=replace(auth_a.authorization,
                capability=auth_other.authorization.capability))),
        ('Bq_A+cap_B', ct_a, replace(auth_other,
            authorization=replace(auth_other.authorization,
                bundle=auth_a.authorization.bundle))),
        ('same_user_different_CT', ct_b, auth_a),
        ('different_user_request_mix', ct_a, replace(auth_a,
            request=auth_other.request)),
        ('different_context', ct_b, auth_a),
        ('cross_session', ct_a, replace(auth_a,
            request=replace(auth_a.request,session_id=auth_b.request.session_id))),
    )
    results = []
    for case_id, ct, auth in mixing:
        with pytest.raises(MyABE08Error, match='.') as info:
            scheme.Transform(ciphertext=ct, public_auth=auth)
        results.append(dict(case_id=case_id, object='CT/Auth', field='binding',
            expected_result='REJECT', actual_result='REJECT',
            error_class=type(info.value).__name__))
    partial = scheme.Transform(ciphertext=ct_a, public_auth=auth_a)
    assert scheme.FinalDec(partial=partial, recovery_key=user.recovery_key) == b'closure-message'
    results.append(dict(case_id='first_consumption', object='Auth', field='request_nonce',
        expected_result='ACCEPT', actual_result='ACCEPT', error_class=None))
    with pytest.raises(MyABE08Error) as info:
        scheme.Transform(ciphertext=ct_a, public_auth=auth_a)
    results.append(dict(case_id='consumed_nonce_replay', object='Auth',
        field='request_nonce', expected_result='REJECT', actual_result='REJECT',
        error_class=type(info.value).__name__))
    bad_keys = (
        ('other_user_RK', other.recovery_key),
        ('valid_wrong_scalar_RK', replace(user.recovery_key,
            rk=scheme.crypto.scalar_from_int(2))),
        ('invalid_RK_encoding', replace(user.recovery_key,
            rk=replace(user.recovery_key.rk, encoded=b'\xff'*32))),
    )
    for case_id, bad_key in bad_keys:
        with pytest.raises(MyABE08Error) as info:
            scheme.FinalDec(partial=partial, recovery_key=bad_key)
        results.append(dict(case_id=case_id, object='RK', field='rk',
            expected_result='REJECT', actual_result='REJECT',
            error_class=type(info.value).__name__))
    report = tmp_path/'PUBLIC_MIXING_REPLAY_RK_MATRIX.json'
    report.write_text(json.dumps(results, sort_keys=True))
    assert len(json.loads(report.read_text())) == len(mixing)+2+len(bad_keys)
    assert CANARY_UID not in report.read_text()


def test_public_privacy_transcript_canaries(public_objects, capsys):
    scheme, user, holder, ct, auth = public_objects
    forbidden = (CANARY_UID, CANARY_ATTRIBUTE)
    # Only public-facing values are collected; secret internals are never printed.
    partial = scheme.Transform(ciphertext=ct, public_auth=auth)
    observations = (repr(user), repr(auth), repr(ct), repr(partial),
        repr(scheme.workload_metadata(partial, policy_shape='single')),
        repr(scheme.authorize_breakdown_ns), repr(scheme.spans_ns),
        repr(scheme.metadata))
    output = capsys.readouterr()
    errors = []
    damaged = replace(ct, publication_signature=_flip(ct.publication_signature))
    for operation in (
        lambda: scheme.Transform(ciphertext=damaged, public_auth=auth),
        lambda: parse_ciphertext(b'bad', scheme.crypto,
                                 expected_profile=EMULATED_TEE_PROFILE),
        lambda: scheme.TEEAuthorize(user=replace(user, credential=replace(
            user.credential, signature=_flip(user.credential.signature))),
            ciphertext=ct, auth_private_key=holder, expiry=1500),
    ):
        with pytest.raises(MyABE08Error) as info:
            operation()
        errors.append(type(info.value).__name__ + ':' + str(info.value))
    other_label = Attribute('private-namespace', 'label', 'PRIVATE-UNAUTHORIZED-4EFR')
    context_id = b'U'*32
    context = PolicyContext(SYS_ID, context_id, 2,
                            compute_ctx_priv(SYS_ID, context_id, 2))
    unrelated = scheme.Encrypt(message=b'denied',
        policy=PolicyInput(((1,),), (other_label,)), context=context,
        data_id=b'unauthorized')
    unrelated_auth = scheme.TEEAuthorize(user=user, ciphertext=unrelated,
        auth_private_key=holder, expiry=1500)
    with pytest.raises(MyABE08Error) as info:
        scheme.Transform(ciphertext=unrelated, public_auth=unrelated_auth)
    errors.append(type(info.value).__name__ + ':' + str(info.value))
    update = scheme.Rev(uid=CANARY_UID, operation=REVOKE)
    scheme.RevStateUpt(update)
    with pytest.raises(MyABE08Error) as info:
        scheme.TEEAuthorize(user=user, ciphertext=ct,
                            auth_private_key=holder, expiry=1500)
    errors.append(type(info.value).__name__ + ':' + str(info.value))
    scheme._ready = False  # Simulate the public fail-closed state gate.
    with pytest.raises(MyABE08Error) as info:
        scheme.TEEAuthorize(user=user, ciphertext=ct,
                            auth_private_key=holder, expiry=1500)
    errors.append(type(info.value).__name__ + ':' + str(info.value))
    transcript = '\n'.join(observations + (repr(errors),)) + output.out + output.err
    assert all(canary not in transcript for canary in forbidden)
    assert hashlib.sha256(user.blob.opaque).hexdigest() not in transcript
    assert scheme._k_tok.hex() not in transcript
    assert scheme._k_rev.hex() not in transcript
