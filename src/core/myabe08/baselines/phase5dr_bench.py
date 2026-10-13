"""Isolated Phase 5D-R algebra-core measurements; no SGX or full-CT claim.

The two tracks use one BLS backend, host, timer, warmup/repetition policy,
and identical structural inputs within each paired configuration. Samples are
never trimmed. Only correctness-gated samples are written.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from functools import lru_cache
import os
from pathlib import Path
import statistics
import time
import uuid

from . import fabeo
from ..af import ProtectedPayloadAF, compute_ctx_af
from ..algebra import (AlgebraOperationCounts, derive_ephemeral_algebra,
                       encrypt_algebra_core, finaldec_algebra_core,
                       keygen_algebra_core, setup_algebra_core,
                       transform_algebra_core)
from ..crypto import BLS12381Backend, compute_ctx_priv, contextual_token
from ..encoding import encode_attribute
from ..experiments.provenance import (REPO, code_manifest, environment_manifest,
                                      file_sha256, spec_manifest)
from ..lsss import LSSSMatrix, prepare_policy_rows
from ..publication import make_af_header
from ..types import PolicyContext

ROOT = REPO / 'artifacts/myabe08/baselines/phase5d_r'
SYS_ID = b'MYABE08-PHASE5DR-COMMON-BLS'
CANARY = b'PHASE5DR-TEST-TOKEN-KEY-ONLY-000'[:32]


def _sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def _matrix(backend, ell, shape):
    if shape == 'OR':
        rows = ((1,),) * ell
    elif shape == 'AND':
        rows = []
        for i in range(ell):
            row = [0] * ell
            if i == 0:
                row[0], row[1] = 1, 1
            elif i == ell - 1:
                row[i] = -1
            else:
                row[i], row[i + 1] = -1, 1
            rows.append(tuple(row))
        rows = tuple(rows)
    else:
        raise ValueError('unknown shape')
    return LSSSMatrix(rows, backend.scalar_order, ell, len(rows[0]))


@lru_cache(maxsize=128)
def _policy(backend, matrix, labels, cmax):
    context_id = hashlib.sha256(b'PHASE5DR-CONTEXT-' +
                                str((labels, cmax)).encode()).digest()
    ctx = PolicyContext(SYS_ID, context_id, 1,
                        compute_ctx_priv(SYS_ID, context_id, 1))
    tokens = tuple(contextual_token(CANARY, SYS_ID, ctx.ctx_priv,
                   encode_attribute('bench', 'label', label)) for label in labels)
    entries, ranks = prepare_policy_rows(matrix, tokens, cmax)
    header = make_af_header(matrix, tokens, ctx, cmax, backend)
    ctx_af = compute_ctx_af(header)
    index = ProtectedPayloadAF().build(entries, header=header, ctx_af=ctx_af)
    return tokens, ranks, index, header, ctx_af


@lru_cache(maxsize=32)
def _ablation_state(backend, cmax):
    pp, msk = setup_algebra_core(backend, cmax)
    base, recovery = keygen_algebra_core(pp, msk, backend)
    return pp, base, recovery


def plan():
    ablation = []
    for ell in (10, 20, 40, 80, 160):
        for divisor in (1, 2, 4, 8):
            d = (ell + divisor - 1) // divisor
            labels = tuple('A' + str(i % d) for i in range(ell))
            cmax = max(labels.count(label) for label in set(labels))
            ablation.append(dict(track='ablation', ell=ell, distinct=d,
                                 cmax=cmax, labels=labels, shape='OR'))
    core = [dict(track='core', ell=ell,
                 labels=tuple('A' + str(i) for i in range(ell)),
                 cmax=1, shape='AND') for ell in (5, 10, 20, 40, 80, 100)]
    out = dict(phase='PHASE_5D_R', profile='ALGEBRA_CORE_ONLY',
               warmups=5, repetitions=30, blocks=3,
               timer='time.perf_counter_ns',
               backend='py_ecc-8.0.0/BLS12-381/Python-3.8.10',
               source_randomness='OS_CSPRNG_UNSEEDED',
               configurations=ablation + core)
    out['plan_sha256'] = _sha(out)
    return out


def _run_ablation(backend, config, mode):
    ell, cmax = config['ell'], config['cmax']
    matrix = _matrix(backend, ell, 'OR')
    labels = tuple(config['labels'])
    tokens, ranks, index, header, ctx_af = _policy(backend, matrix, labels, cmax)
    pp, base, recovery = _ablation_state(backend, cmax)
    # OR access needs one authorized token. Keep the same user/AF for both arms.
    bundle_tokens = (tokens[0],)
    started = time.perf_counter_ns()
    enc_counts = AlgebraOperationCounts()
    ct = encrypt_algebra_core(pp, matrix, tokens, backend,
                              counts=enc_counts, component_allocation=mode)
    encrypt_ns = time.perf_counter_ns() - started
    bundle = derive_ephemeral_algebra(pp, base, bundle_tokens, ct.c, backend)
    started = time.perf_counter_ns()
    transform_counts = AlgebraOperationCounts()
    tr = transform_algebra_core(pp, ct, bundle, index, header, ctx_af,
        backend, counts=transform_counts, component_allocation=mode)
    transform_ns = time.perf_counter_ns() - started
    _, recovered = finaldec_algebra_core(bundle.t0_q, tr.t_a, recovery, backend)
    if recovered != ct.e:
        raise AssertionError('ablation decryption failed')
    if transform_counts.pairing_terms != 1 + len(tr.occurrence_slots):
        raise AssertionError('ablation pairing ledger mismatch')
    return dict(encrypt_ns=encrypt_ns, transform_ns=transform_ns,
        core_ct_bytes=(sum(len(x.encoded) for x in ct.c_i) +
                       sum(len(x.encoded) for x in ct.d_j) +
                       len(ct.c.encoded)),
        g1_count=ell+1, g2_count=len(ct.d_j), gt_count=0,
        internal_kem_gt_count=1,
        d_component_bytes=sum(len(x.encoded) for x in ct.d_j),
        g1_exp=enc_counts.g1_exponentiations,
        g2_exp=enc_counts.g2_exponentiations,
        gt_exp=enc_counts.gt_exponentiations,
        encrypt_random_scalars=matrix.d+len(ct.d_j),
        csp_pairings=transform_counts.pairing_terms,
        tee_pairings=1, finaldec_pairings=0,
        actual_tI=len(tr.occurrence_slots), actual_J=len(tr.candidate_rows),
        actual_I=len(tr.reconstruction_rows), occurrence_ranks=ranks)


def _run_core(backend, config, scheme):
    ell = config['ell']
    labels = tuple(config['labels'])
    matrix = _matrix(backend, ell, 'AND')
    if scheme == 'MYABE08_BLS12381_CORE':
        tokens, _, index, header, ctx_af = _policy(backend, matrix, labels, 1)
        start = time.perf_counter_ns()
        pp, msk = setup_algebra_core(backend, 1)
        setup_ns = time.perf_counter_ns() - start
        start = time.perf_counter_ns()
        base, rk = keygen_algebra_core(pp, msk, backend)
        keygen_ns = time.perf_counter_ns() - start
        start = time.perf_counter_ns()
        ct = encrypt_algebra_core(pp, matrix, tokens, backend)
        encrypt_ns = time.perf_counter_ns() - start
        start = time.perf_counter_ns()
        bundle = derive_ephemeral_algebra(pp, base, tuple(sorted(set(tokens))), ct.c,
                                          backend)
        counts = AlgebraOperationCounts()
        tr = transform_algebra_core(pp, ct, bundle, index, header, ctx_af,
                                    backend, counts=counts)
        _, recovered = finaldec_algebra_core(bundle.t0_q, tr.t_a, rk, backend)
        access_ns = time.perf_counter_ns() - start
        if recovered != ct.e:
            raise AssertionError('MyABE core access failed')
        return dict(setup_ns=setup_ns, keygen_ns=keygen_ns,
                    encrypt_ns=encrypt_ns, access_ns=access_ns,
                    ct_group_bytes=ell*48 + 96 + 48,
                    du_core_key_bytes=32, tee_core_key_bytes=128,
                    total_core_key_bytes=160,
                    g1_count=ell+1, g2_count=1, gt_count=0,
                    internal_kem_gt_count=1,
                    access_pairings=1+counts.pairing_terms)
    if scheme == 'FABEO22_CP_BLS12381_TAU1':
        start = time.perf_counter_ns()
        pp, alpha = fabeo.setup(backend)
        setup_ns = time.perf_counter_ns() - start
        start = time.perf_counter_ns()
        key = fabeo.keygen(pp, alpha, labels)
        keygen_ns = time.perf_counter_ns() - start
        message = backend.pair(pp.g1, pp.g2)
        start = time.perf_counter_ns()
        ct = fabeo.encrypt(pp, matrix, labels, message)
        encrypt_ns = time.perf_counter_ns() - start
        start = time.perf_counter_ns()
        recovered = fabeo.decrypt(pp, ct, key)
        access_ns = time.perf_counter_ns() - start
        if recovered != message or len(ct.g2_sprime) != 1:
            raise AssertionError('FABEO tau1 access failed')
        return dict(setup_ns=setup_ns, keygen_ns=keygen_ns,
                    encrypt_ns=encrypt_ns, access_ns=access_ns,
                    ct_group_bytes=ell*48 + 2*96 + 576,
                    du_core_key_bytes=(ell+1)*48 + 96,
                    tee_core_key_bytes=0,
                    total_core_key_bytes=(ell+1)*48 + 96,
                    g1_count=ell, g2_count=2, gt_count=1,
                    internal_kem_gt_count=0,
                    access_pairings=3)
    raise ValueError('unknown scheme')


def _write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--track', choices=('ablation', 'core'), required=True)
    parser.add_argument('--output', type=Path, default=ROOT)
    parser.add_argument('--max-configs', type=int, default=None,
                        help='Explicit reduced diagnostic run; not formal complete data')
    args = parser.parse_args(argv)
    frozen = plan()
    spec = spec_manifest()  # hard fail on unexpected specification change
    if not hasattr(os, 'sched_getaffinity') or not hasattr(os, 'sched_setaffinity'):
        raise RuntimeError('CPU affinity is required for this common-backend run')
    selected_cpu = min(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {selected_cpu})
    backend = BLS12381Backend(SYS_ID)
    configurations = [c for c in frozen['configurations'] if c['track'] == args.track]
    if args.max_configs is not None:
        configurations = configurations[:args.max_configs]
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:12]
    run = args.output / args.track / run_id
    run.mkdir(parents=True, exist_ok=False)
    _write_json(run/'PHASE5D_R_PLAN.json', frozen)
    _write_json(run/'PHASE5D_R_CODE_MANIFEST.json', code_manifest())
    _write_json(run/'ENVIRONMENT.json', environment_manifest())
    _write_json(run/'BASELINE_SOURCE_MANIFEST.json', dict(
        specification=spec,
        myabe_algebra_sha256=file_sha256(REPO/'src/core/myabe08/algebra.py'),
        fabeo_port_sha256=file_sha256(REPO/'src/core/myabe08/baselines/fabeo.py'),
        fabeo_native_sha256=file_sha256(REPO/'src/core/fabeo22cp/__init__.py')))
    samples = []
    warmups, repeats = frozen['warmups'], frozen['repetitions']
    for config in configurations:
        schemes = (('OCCURRENCE', 'ROW') if args.track == 'ablation' else
                   ('MYABE08_BLS12381_CORE', 'FABEO22_CP_BLS12381_TAU1'))
        for block in range(3):
            ordered_schemes = schemes if block % 2 == 0 else tuple(reversed(schemes))
            for scheme in ordered_schemes:
                block_warmups = warmups if block == 0 else 0
                for attempt in range(block_warmups + repeats//3):
                    measurement = (_run_ablation(backend, config, scheme)
                                   if args.track == 'ablation' else
                                   _run_core(backend, config, scheme))
                    if attempt < block_warmups:
                        continue
                    samples.append(dict(config_id=_sha(config)[:20], config=config,
                                        scheme=scheme, block=block,
                                        repetition=attempt-block_warmups,
                                        measurement_origin='LOCAL_MEASURED',
                                        implementation_origin=(
                                            'INTERNAL_ABLATION' if scheme=='ROW' else
                                            'COMMON_BACKEND_PORT' if scheme.startswith('FABEO')
                                            else 'CURRENT_MYABE08_IMPLEMENTATION'),
                                        security_profile='SECURITY_PROFILE_BLS12_381',
                                        tee_profile='NO_TEE_ALGEBRA_CORE_ONLY',
                                        **measurement))
        with (run/'raw.jsonl').open('w') as out:
            for row in samples:
                out.write(json.dumps(row, sort_keys=True) + '\n')
        print(args.track, config['ell'], config['cmax'], 'complete', flush=True)
    _write_json(run/'MANIFEST.json', dict(run_id=run_id, track=args.track,
        status=('COMPLETE' if args.max_configs is None else 'DIAGNOSTIC_REDUCED'),
        plan_sha256=frozen['plan_sha256'], configurations=len(configurations),
        samples=len(samples), cpu_affinity=[selected_cpu],
        raw_sha256=file_sha256(run/'raw.jsonl')))
    print(run)


if __name__ == '__main__':
    main()
