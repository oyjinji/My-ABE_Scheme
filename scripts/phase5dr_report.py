"""Phase 5D-R reports from validated, immutable algebra-core analyses.

This script never benchmarks and never edits source runs or analyses. It lives
outside the sampled source tree, whose exact bytes are archived with the run.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def load_analysis(path, track):
    validation = json.loads((path / 'VALIDATION.json').read_text())
    if (validation.get('status') != 'PASS' or
            validation.get('outliers_removed') != 0 or
            not Path(validation['source_run']).exists()):
        raise ValueError('complete all-sample validated analysis required')
    run = Path(validation['source_run'])
    manifest = json.loads((run / 'MANIFEST.json').read_text())
    if (manifest['status'] != 'COMPLETE' or manifest['track'] != track or
            manifest['raw_sha256'] != sha256(run / 'raw.jsonl') or
            manifest['raw_sha256'] != validation['raw_sha256']):
        raise ValueError('source run validation mismatch')
    statistics = json.loads((path / 'statistics.json').read_text())
    expected_groups = 40 if track == 'ablation' else 12
    if len({(r['config_id'], r['scheme']) for r in statistics}) != expected_groups:
        raise ValueError('incomplete statistical groups')
    if any(r['n'] != 30 for r in statistics):
        raise ValueError('expected 30 untrimmed samples per group')
    return statistics, dict(analysis=str(path), source_run=str(run),
        raw_sha256=manifest['raw_sha256'],
        statistics_sha256=sha256(path / 'statistics.json'),
        source_tree_sha256=json.loads((run / 'PHASE5D_R_CODE_MANIFEST.json').read_text())['tree_sha256'])


def lookup(statistics, scheme, metric, ell, cmax=None):
    matches = [r for r in statistics if r['scheme'] == scheme and
               r['metric'] == metric and r['config']['ell'] == ell and
               (cmax is None or r['config']['cmax'] == cmax)]
    if len(matches) != 1:
        raise ValueError('missing or ambiguous configuration: %s %s %s %s' %
                         (scheme, metric, ell, cmax))
    return matches[0]['median']


def paired_rows(stats, left, right, metrics):
    configs = sorted({(r['config']['ell'], r['config']['cmax']) for r in stats})
    rows = []
    for ell, cmax in configs:
        for metric in metrics:
            a = lookup(stats, left, metric, ell, cmax)
            b = lookup(stats, right, metric, ell, cmax)
            rows.append(dict(ell=ell, cmax=cmax, metric=metric,
                left_scheme=left, right_scheme=right, left_median=a,
                right_median=b, difference_right_minus_left=b-a,
                reduction_left_vs_right_percent=(b-a)/b*100 if b else None,
                ratio_right_over_left=b/a if a else None,
                n_per_scheme=30, measurement_origin='LOCAL_MEASURED',
                comparison_scope='ALGEBRA_CORE_ONLY'))
    return rows


def csv_write(path, rows):
    if not rows:
        raise ValueError('no report rows')
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=tuple(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def structural_ledger(analysis, out, track):
    run=Path(json.loads((analysis/'VALIDATION.json').read_text())['source_run'])
    by_group={}
    with (run/'raw.jsonl').open() as stream:
        for line in stream:
            row=json.loads(line)
            key=(row['config_id'],row['scheme'])
            if track=='ablation':
                fields=('g1_count','g2_count','gt_count','internal_kem_gt_count',
                    'g1_exp','g2_exp','gt_exp','encrypt_random_scalars',
                    'csp_pairings','tee_pairings','finaldec_pairings',
                    'd_component_bytes','core_ct_bytes')
            else:
                fields=('g1_count','g2_count','gt_count','internal_kem_gt_count',
                    'access_pairings','ct_group_bytes','du_core_key_bytes',
                    'tee_core_key_bytes','total_core_key_bytes')
            values={name:row[name] for name in fields}
            if key in by_group and by_group[key]['values']!=values:
                raise ValueError('nonconstant structural ledger within group')
            by_group[key]=dict(config=row['config'],scheme=row['scheme'],values=values)
    result=[]
    for _,entry in sorted(by_group.items()):
        c,v=entry['config'],entry['values']
        record=dict(ell=c['ell'],cmax=c['cmax'],scheme=entry['scheme'],
            g1_public_bytes=v['g1_count']*48,g2_public_bytes=v['g2_count']*96,
            group_encoding='compressed G1 48 B / compressed G2 96 B / GT 576 B',
            **v)
        if track=='ablation':
            record['encrypt_hash_to_g1_calls_source_derived']=c['ell']
            record['hash_count_origin']='SOURCE_DERIVED_NOT_INSTRUMENTED'
            record['full_ciphertext_bytes']='NOT_AVAILABLE_CORE_ONLY'
        result.append(record)
    csv_write(out/('%s_operation_ledger.csv'%track),result)
    return len(result)


def _text(path, body):
    path.write_text(body.rstrip() + '\n')


def advantage_reports(out, ablation, core):
    ct = [r for r in ablation if r['metric'] == 'core_ct_bytes']
    encrypt = {(r['ell'],r['cmax']):r for r in ablation if r['metric']=='encrypt_ns'}
    transform = {(r['ell'],r['cmax']):r for r in ablation if r['metric']=='transform_ns'}
    advantages = ['# Supported local algebra-core advantages', '',
        'The first table compares the same OR-policy configuration on BLS12-381/py_ecc, '
        'with 30 samples per arm and no sample deletion. Bytes are encoded public '
        'ABE group components (`C_i`, `D_j`, `C`), **not** complete signed ciphertexts.', '',
        '| ell | actual cmax | MyABE core bytes | Row ablation bytes | Reduction |',
        '|---:|---:|---:|---:|---:|']
    for r in (item for item in ct if item['reduction_left_vs_right_percent']>0):
        advantages.append('| %d | %d | %.0f | %.0f | %.2f%% |' %
            (r['ell'],r['cmax'],r['left_median'],r['right_median'],
             r['reduction_left_vs_right_percent']))
    advantages += ['', 'A positive timing reduction is an observed local median '
        'difference, never an asymptotic or production-SGX speedup. Complete '
        'signed CT byte sizes are separately single-constructed under EMULATED '
        'TEST; full-system ablation latency was not measured.', '',
        '## Common-backend AND core timing with lower MyABE median', '',
        'Both arms are locally measured on the same backend. Functions and key '
        'placement differ; these are metric-specific observations.', '',
        '| metric | ell | MyABE median (ms) | FABEO median (ms) |',
        '|---|---:|---:|---:|']
    for r in (item for item in core if item['metric'] in
              ('setup_ns','keygen_ns','encrypt_ns','access_ns') and
              item['reduction_left_vs_right_percent']>0):
        advantages.append('| %s | %d | %.3f | %.3f |' %
            (r['metric'],r['ell'],r['left_median']/1e6,
             r['right_median']/1e6))
    _text(out/'SUPPORTED_ADVANTAGES.md', '\n'.join(advantages))

    tradeoffs = ['# Supported local algebra-core tradeoffs', '',
        'Same-configuration medians; positive difference means the row ablation '
        'is slower than occurrence-aware MyABE. Timing is in milliseconds. '
        'The OR workload authorizes one row. Both arms use two CSP pairings; '
        'the row arm validates/serializes many more D elements, so these '
        'Transform medians do not demonstrate a pairing-count reduction or '
        'probe large `tI`.', '',
        '| ell | cmax | Encrypt MyABE | Encrypt row | Transform MyABE | Transform row |',
        '|---:|---:|---:|---:|---:|---:|']
    for r in ct:
        e=encrypt[r['ell'],r['cmax']]
        t=transform[r['ell'],r['cmax']]
        tradeoffs.append('| %d | %d | %.3f | %.3f | %.3f | %.3f |' %
            (r['ell'],r['cmax'],e['left_median']/1e6,e['right_median']/1e6,
             t['left_median']/1e6,t['right_median']/1e6))
    tradeoffs += ['', 'The common-backend AND core access medians expose the '
        'opposite local timing result. MyABE access includes synthetic T0, '
        'AF.Query, CSP transform and DU recovery; FABEO access is direct '
        'decrypt. These are distinct functions, not full-system peers.', '',
        '| ell | MyABE core access (ms) | FABEO direct decrypt (ms) |',
        '|---:|---:|---:|']
    for r in (item for item in core if item['metric']=='access_ns'):
        tradeoffs.append('| %d | %.3f | %.3f |' %
            (r['ell'],r['left_median']/1e6,r['right_median']/1e6))
    _text(out/'SUPPORTED_TRADEOFFS.md', '\n'.join(tradeoffs))

    no_advantage=['# No observed median advantage in measured comparisons', '',
        'Ablation rows are retained, not filtered. A nonpositive reduction means '
        'the occurrence-aware arm was equal or slower at that exact configuration. '
        'Small local median differences are descriptive, not significance tests.', '',
        '| metric | ell | actual cmax | MyABE median | row median | unit |',
        '|---|---:|---:|---:|---:|---|']
    misses=[r for r in ablation if r['metric'] in ('encrypt_ns','transform_ns',
                                                   'core_ct_bytes') and
            r['reduction_left_vs_right_percent']<=0]
    for r in misses:
        scale=1e6 if r['metric'].endswith('_ns') else 1
        unit='ms' if scale==1e6 else 'bytes'
        no_advantage.append('| %s | %d | %d | %.3f | %.3f | %s |' %
            (r['metric'],r['ell'],r['cmax'],r['left_median']/scale,
             r['right_median']/scale,unit))
    if not misses:
        no_advantage.append('| None in the measured metrics | — | — | — | — | — |')
    no_advantage += ['', '## Common-backend AND core timing', '',
        'The following configurations have no observed MyABE median timing '
        'advantage over FABEO. Distinct cryptographic functions and key '
        'placement remain relevant.', '',
        '| metric | ell | MyABE median (ms) | FABEO median (ms) |',
        '|---|---:|---:|---:|']
    core_misses=[r for r in core if r['metric'] in
                 ('setup_ns','keygen_ns','encrypt_ns','access_ns') and
                 r['reduction_left_vs_right_percent']<=0]
    for r in core_misses:
        no_advantage.append('| %s | %d | %.3f | %.3f |' %
            (r['metric'],r['ell'],r['left_median']/1e6,
             r['right_median']/1e6))
    if not core_misses:
        no_advantage.append('| None | — | — | — |')
    _text(out/'NO_OBSERVED_ADVANTAGE.md','\n'.join(no_advantage))

    blocked = '''# Blocked or limited comparisons

| Pair or metric | Status | Reason |
|---|---|---|
| MyABE full signed CT vs row-ablation full signed CT latency | NOT_MEASURED | A separate one-construction-per-configuration EMULATED TEST artifact records complete canonical wire size only; it is not a latency distribution. |
| MyABE full request vs FABEO direct decrypt | NOT_COMPARABLE | Privacy, revocation, capability, publication, RPC and SGX trust boundaries differ. |
| MyABE core vs full feature overhead ratio | NOT_COMPARABLE | Existing full SGX workload is not paired with the AND core workload; no causal subtraction is valid. |
| FABEO native MNT224 vs BLS12-381 port wall clock | NOT_COMPARABLE | Different curves and runtimes. Native source is a tau=1 correctness/cardinality oracle. |
| HR-ABE Type-A vs MyABE Type-III wall clock | BLOCKED_TYPE_MAPPING | A secure paper-faithful Type-III hash/group mapping was not established. |
| LUAR local wall clock | BLOCKED_CORRECTNESS | Published LSSS reconstruction fails a valid AND policy; no authoritative correction found. Literature reference only. |

MyABE remains **CANDIDATE — FORMAL PROOF OPEN**. Prior real SGX results use a
DEBUG enclave with QVL OUT_OF_DATE and strict RA2 BLOCKED; this algebra-core
dataset contains no SGX measurement. Stable same-user/same-CT `W` linkability
remains an observed leakage.
'''
    _text(out/'BLOCKED_COMPARISONS.md', blocked)

    core_rows=['# MyABE ABE core versus FABEO tau=1 common BLS12-381', '',
        'Both arms use Python 3.8.10, py_ecc 8.0.0, BLS12-381, the same '
        'unique-attribute AND policy, 5 warmups, 30 measured samples in 3 blocks, '
        'and the same pinned CPU. They implement different feature sets and key '
        'placement. The figures are local algebra-core observations only.', '',
        '| ell | metric | MyABE median | FABEO median | unit | FABEO/MyABE |',
        '|---:|---|---:|---:|---|---:|']
    for r in core:
        scale=1e6 if r['metric'].endswith('_ns') else 1
        unit='ms' if scale==1e6 else ('bytes' if r['metric'].endswith('_bytes')
                                      else 'pairing calls')
        core_rows.append('| %d | %s | %.3f | %.3f | %s | %.3f |' %
            (r['ell'],r['metric'],r['left_median']/scale,
             r['right_median']/scale,unit,r['ratio_right_over_left']))
    core_rows += ['', 'The MyABE key total includes enclave-side algebra base '
        'material plus DU RK; FABEO key material is DU-side. `access_ns` includes '
        'MyABE synthetic T0, AF query, CSP transform and DU recovery, versus FABEO decrypt. '
        'Ciphertext group bytes are structural only: FABEO includes a masked GT '
        'message, while MyABE stores its byte-message DEM outside this core count. '
        'No capability, AF build, tokenization, revocation, RPC, DEM or publication '
        'is timed in this track.']
    _text(out/'CORE_COMPARISON.md','\n'.join(core_rows))


def full_ct_report(out, artifact, expected_raw_sha256):
    """Record the separately constructed public wire-size evidence, without timing claims."""
    provenance=json.loads((artifact/'PROVENANCE.json').read_text())
    if (provenance.get('status')!='COMPLETE_SINGLE_CONSTRUCTION_SIZE_ONLY' or
            provenance.get('configurations')!=20 or
            provenance.get('constructions')!=40 or
            provenance.get('timing_samples')!=0 or
            provenance.get('backend')!='EMULATED_TEE_PROFILE' or
            provenance.get('ablation_raw_sha256')!=expected_raw_sha256):
        raise ValueError('complete one-construction public CT size artifact required')
    with (artifact/'full_ct_paired.csv').open(newline='') as stream:
        rows=list(csv.DictReader(stream))
    if len(rows)!=20 or any(r['comparability']!='PAIRED_AF_SHAPE_MATCH' for r in rows):
        raise ValueError('full CT pairs are incomplete or AF shapes differ')
    lines=['# Complete signed public CT wire size', '',
        'Each arm was constructed and decrypted once per OR-policy configuration '
        'using the EMULATED TEST public facade and canonical CT serializer. '
        'This is structural size evidence, **not** a latency benchmark.', '',
        '| ell | actual cmax | Occurrence CT bytes | Row-ablation CT bytes | Reduction |',
        '|---:|---:|---:|---:|---:|']
    for row in sorted(rows,key=lambda r:(int(r['ell']),int(r['actual_cmax']))):
        lines.append('| %s | %s | %s | %s | %.2f%% |'%(
            row['ell'],row['actual_cmax'],row['occurrence_full_ct_bytes'],
            row['row_full_ct_bytes'],float(row['reduction_percent'])))
    lines += ['', 'The row arm uses an explicitly separate TEST-only encoding '
        'marker. AF slot counts and slot-byte totals match within each pair. '
        'Byte differences include the changed D component count and any '
        'serialization-length consequences; they are not a cryptographic '
        'security or wall-clock advantage claim.', '',
        'Source: `%s`; provenance SHA-256: `%s`.' %
        (artifact,sha256(artifact/'PROVENANCE.json'))]
    _text(out/'FULL_CT_COMPARISON.md','\n'.join(lines))
    return dict(artifact=str(artifact),
                provenance_sha256=sha256(artifact/'PROVENANCE.json'),
                paired_sha256=sha256(artifact/'full_ct_paired.csv'))


def key_placement_report(out):
    with (out/'core_operation_ledger.csv').open(newline='') as stream:
        rows=list(csv.DictReader(stream))
    if len(rows)!=12:
        raise ValueError('core key-placement ledger incomplete')
    lines=['# ABE-core key placement (structural bytes)', '',
        'Compressed BLS12-381 group encodings and 32-byte scalar encodings. '
        'These are algebra-core objects, not complete user credentials, sealed '
        'Blobs, or transport envelopes. MyABE places base material in the TEE '
        'architecture and RK with the DU; this local core run did not execute SGX.', '',
        '| ell | Scheme | DU key bytes | TEE-side core bytes | Total core bytes |',
        '|---:|---|---:|---:|---:|']
    for row in sorted(rows,key=lambda r:(int(r['ell']),r['scheme'])):
        lines.append('| %s | %s | %s | %s | %s |' %
            (row['ell'],row['scheme'],row['du_core_key_bytes'],
             row['tee_core_key_bytes'],row['total_core_key_bytes']))
    _text(out/'CORE_KEY_PLACEMENT.md','\n'.join(lines))


def dashboard(out, ablation_stats, core_stats, sources, phase5b):
    fig, axes = plt.subplots(2, 3, figsize=(14,8.2))
    fig.subplots_adjust(left=.07,right=.99,bottom=.17,top=.88,
                        wspace=.28,hspace=.48)
    chart_rows=[]
    colors = {'OCCURRENCE':'#1f77b4','ROW':'#7f7f7f',
        'MYABE08_BLS12381_CORE':'#1f77b4',
        'FABEO22_CP_BLS12381_TAU1':'#ff7f0e'}
    names = {'OCCURRENCE':'MyABE occurrence-aware','ROW':'Row ablation',
        'MYABE08_BLS12381_CORE':'MyABE ABE core',
        'FABEO22_CP_BLS12381_TAU1':'FABEO tau=1 BLS'}
    for scheme in ('OCCURRENCE','ROW'):
        rows=sorted((r for r in ablation_stats if r['metric']=='core_ct_bytes' and
                     r['config']['ell']==80 and r['scheme']==scheme),
                    key=lambda r:r['config']['cmax'])
        chart_rows.extend(dict(panel='occurrence_core_bytes',ell=80,
            cmax=r['config']['cmax'],scheme=scheme,median=r['median'],
            unit='bytes',n=r['n']) for r in rows)
        axes[0,0].plot([r['config']['cmax'] for r in rows],
            [r['median'] for r in rows],marker='o',color=colors[scheme],label=names[scheme])
    axes[0,0].set(title='Occurrence reuse: core group bytes (ell=80)',
                  xlabel='Actual cmax',ylabel='Encoded group bytes (bytes)')
    axes[0,0].legend(frameon=False,fontsize=8)
    for scheme in ('OCCURRENCE','ROW'):
        rows=sorted((r for r in ablation_stats if r['metric']=='encrypt_ns' and
                     r['config']['ell']==80 and r['scheme']==scheme),
                    key=lambda r:r['config']['cmax'])
        chart_rows.extend(dict(panel='occurrence_encrypt',ell=80,
            cmax=r['config']['cmax'],scheme=scheme,median=r['median']/1e6,
            unit='ms',n=r['n']) for r in rows)
        axes[0,1].plot([r['config']['cmax'] for r in rows],
            [r['median']/1e6 for r in rows],marker='o',
            color=colors[scheme],label=names[scheme])
    axes[0,1].set(title='Occurrence reuse: Encrypt (ell=80)',
                  xlabel='Actual cmax',ylabel='Median latency (ms)')
    axes[0,1].legend(frameon=False,fontsize=8)
    for ax,metric,title in ((axes[0,2],'keygen_ns','Core KeyGen'),
                             (axes[1,0],'encrypt_ns','Core Encrypt'),
                             (axes[1,1],'access_ns','Core authorized access')):
        for scheme in ('MYABE08_BLS12381_CORE','FABEO22_CP_BLS12381_TAU1'):
            rows=sorted((r for r in core_stats if r['metric']==metric and
                         r['scheme']==scheme),key=lambda r:r['config']['ell'])
            chart_rows.extend(dict(panel=metric,ell=r['config']['ell'],
                cmax=1,scheme=scheme,median=r['median']/1e6,
                unit='ms',n=r['n']) for r in rows)
            ax.plot([r['config']['ell'] for r in rows],
                [r['median']/1e6 for r in rows],marker='o',
                color=colors[scheme],label=names[scheme])
        ax.set(title=title,xlabel='AND policy rows (ell)',ylabel='Median latency (ms)')
        ax.legend(frameon=False,fontsize=8)
    full_source=phase5b/'figures/figure_Fig_Exp5_F_E2E_Components_data.csv'
    with full_source.open(newline='') as stream:
        full=[r for r in csv.DictReader(stream)
              if r['configuration_id']=='CFG-430c24cc31f3cdea936a' and
              r['component'] in ('TEEAuthorize','Transform','FinalDec')]
    if len(full)!=3:
        raise ValueError('full SGX context components missing')
    full.sort(key=lambda r:('TEEAuthorize','Transform','FinalDec').index(r['component']))
    axes[1,2].bar([r['component'] for r in full],
                  [float(r['median_ms']) for r in full],color='#ff7f0e')
    axes[1,2].set(title='Full SGX request context (2-of-5)',
                  ylabel='Median latency (ms)')
    axes[1,2].tick_params(axis='x',labelrotation=15,labelsize=8)
    chart_rows.extend(dict(panel='full_sgx_request_context',ell=5,cmax=1,
        scheme='MYABE08_FULL_SGX_DEBUG_'+r['component'],
        median=float(r['median_ms']),unit='ms',n='canonical Phase5B') for r in full)
    for ax in axes.flat: ax.grid(alpha=.25)
    fig.suptitle('MyABE-08 Phase 5D-R comparison and full-system context',y=.97)
    fig.text(.5,.035,'SGX panel is an unpaired threshold workload: DEBUG / '
        'QVL OUT_OF_DATE / strict RA2 BLOCKED. Do not subtract cohorts.',
        ha='center',fontsize=8)
    fig.savefig(out/'MYABE_COMPARATIVE_DASHBOARD.png',dpi=300)
    fig.savefig(out/'MYABE_COMPARATIVE_DASHBOARD.pdf')
    plt.close(fig)
    csv_write(out/'MYABE_COMPARATIVE_DASHBOARD.csv',chart_rows)
    (out/'MYABE_COMPARATIVE_DASHBOARD.json').write_text(json.dumps(dict(
        title='Phase 5D-R algebra-core comparison dashboard',
        source_statistics_sha256=dict(ablation=sources['ablation']['statistics_sha256'],
                                      core=sources['core']['statistics_sha256']),
        filters='validated complete data only; no outlier deletion',
        trust='Core panels: NO_TEE; context panel: SGX DEBUG, QVL OUT_OF_DATE, strict RA2 BLOCKED',
        comparability='Core pairs local common backend; SGX panel unpaired',
        full_context_source_sha256=sha256(full_source)),
        sort_keys=True,indent=2)+'\n')
    _text(out/'MYABE_COMPARATIVE_DASHBOARD.md',
        'The first five panels use validated local BLS12-381/py_ecc algebra-core '
        'measurements. The row variant is an internal ablation. The final panel '
        'shows canonical Phase 5B full SGX stage medians from a separate 2-of-5 '
        'threshold workload; it is context, not a paired overhead estimate. '
        'SGX is DEBUG with QVL OUT_OF_DATE and strict RA2 BLOCKED.\n\n'
        'Source statistics SHA-256: ablation `%s`; core `%s`.' %
        (sources['ablation']['statistics_sha256'],sources['core']['statistics_sha256']))


def feature_context(out, core_stats, phase5b):
    """Show available cost placement without subtracting unmatched cohorts."""
    manifest=json.loads((phase5b/'analysis_manifest.json').read_text())
    if (manifest.get('analysis_id') != '20260926T061408Z-8bb066fbcd25' or
            manifest.get('analysis_schema') != 'MYABE08-ANALYSIS-V1'):
        raise ValueError('unexpected Phase 5B canonical analysis')
    source=phase5b/'figures/figure_Fig_Exp5_F_E2E_Components_data.csv'
    with source.open(newline='') as stream:
        rows=list(csv.DictReader(stream))
    full=[r for r in rows if r['configuration_id']=='CFG-430c24cc31f3cdea936a'
          and r['component'] in ('E2E','TEEAuthorize','Transform','FinalDec')]
    if len(full)!=4 or any(r['N']!='5' for r in full):
        raise ValueError('full profile source configuration unavailable')
    core_ms=lookup(core_stats,'MYABE08_BLS12381_CORE','access_ns',5,1)/1e6
    labels=['Core access\nAND, ell=5']+[r['component']+'\nthreshold 2-of-5' for r in full]
    values=[core_ms]+[float(r['median_ms']) for r in full]
    source_rows=[dict(cohort='CORE_AND_ELL5' if i==0 else
                      'SGX_FULL_THRESHOLD_2_OF_5',stage=labels[i],
                      median_ms=values[i],n=30 if i==0 else 'canonical Phase5B')
                 for i in range(len(labels))]
    csv_write(out/'MYABE_CORE_TO_FULL_CONTEXT.csv',source_rows)
    csv_write(out/'MYABE_CORE_TO_FULL_OVERHEAD.csv',source_rows)
    fig,ax=plt.subplots(figsize=(9,5.2))
    fig.subplots_adjust(left=.11,right=.98,bottom=.28,top=.88)
    bars=ax.bar(range(len(labels)),values,color=['#1f77b4']+['#ff7f0e']*4)
    ax.set_xticks(range(len(labels)),labels,fontsize=8)
    ax.set_ylabel('Median latency (ms)')
    ax.set_title('MyABE core and full-profile cost placement (unpaired)')
    ax.grid(axis='y',alpha=.25)
    ax.set_axisbelow(True)
    fig.text(.5,.04,'Different workloads and cohorts; do not subtract bars. '
        'SGX DEBUG / QVL OUT_OF_DATE / strict RA2 BLOCKED.',
        ha='center',fontsize=8)
    fig.savefig(out/'MYABE_CORE_TO_FULL_CONTEXT.png',dpi=300,bbox_inches='tight')
    fig.savefig(out/'MYABE_CORE_TO_FULL_CONTEXT.pdf',bbox_inches='tight')
    # The requested overhead view exists as an explicit non-estimability
    # figure. The unlike AND/threshold cohorts cannot support subtraction.
    fig.savefig(out/'MYABE_CORE_TO_FULL_OVERHEAD.png',dpi=300,bbox_inches='tight')
    fig.savefig(out/'MYABE_CORE_TO_FULL_OVERHEAD.pdf',bbox_inches='tight')
    plt.close(fig)
    (out/'MYABE_CORE_TO_FULL_CONTEXT.json').write_text(json.dumps(dict(
        title='Unpaired MyABE core/full cost placement',
        core_analysis='Phase 5D-R validated core',
        full_analysis=str(phase5b),full_source_sha256=sha256(source),
        full_analysis_manifest_sha256=sha256(phase5b/'analysis_manifest.json'),
        comparability='NOT_DIRECTLY_COMPARABLE',
        reason='AND ell=5 core versus threshold 2-of-5 real SGX full profile; '
               'no paired full/core feature-overhead ratio is available',
        sgx_trust='SGX_DEBUG_GRAMINE_V1; QVL OUT_OF_DATE; strict RA2 BLOCKED'),
        sort_keys=True,indent=2)+'\n')
    (out/'MYABE_CORE_TO_FULL_OVERHEAD.json').write_text(json.dumps(dict(
        status='NOT_ESTIMABLE_FROM_UNPAIRED_COHORTS',
        plot_type='NONADDITIVE_COST_PLACEMENT',
        source_data='MYABE_CORE_TO_FULL_CONTEXT.csv',
        missing_paired_components=['tokenization','AF build','revocation check',
            'cap/signature','RPC','DEM'],
        reason='AND ell=5 local core and real SGX threshold 2-of-5 full request '
               'differ in workload and cohort; stages may overlap',
        sgx_trust='SGX_DEBUG_GRAMINE_V1; QVL OUT_OF_DATE; strict RA2 BLOCKED'),
        sort_keys=True,indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--ablation',type=Path,required=True)
    parser.add_argument('--core',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--full-ct',type=Path,required=True,
                        help='Validated single-construction EMULATED public CT size artifact')
    parser.add_argument('--phase5b',type=Path,default=Path(
        'artifacts/myabe08/analysis/phase5b/20260926T061408Z-8bb066fbcd25'))
    args=parser.parse_args()
    a,aprovenance=load_analysis(args.ablation,'ablation')
    c,cprovenance=load_analysis(args.core,'core')
    if aprovenance['source_tree_sha256'] != cprovenance['source_tree_sha256']:
        raise ValueError('paired tracks used different frozen source trees')
    args.output.mkdir(parents=True,exist_ok=False)
    ablation=paired_rows(a,'OCCURRENCE','ROW',
                         ('core_ct_bytes','g2_count','encrypt_ns','transform_ns'))
    core=paired_rows(c,'MYABE08_BLS12381_CORE','FABEO22_CP_BLS12381_TAU1',
                     ('setup_ns','keygen_ns','encrypt_ns','access_ns',
                      'ct_group_bytes','total_core_key_bytes','access_pairings'))
    csv_write(args.output/'ablation_paired.csv',ablation)
    csv_write(args.output/'core_paired.csv',core)
    structural_ledger(args.ablation,args.output,'ablation')
    structural_ledger(args.core,args.output,'core')
    key_placement_report(args.output)
    full_ct_source=full_ct_report(args.output,args.full_ct,
                                  aprovenance['raw_sha256'])
    sources=dict(ablation=aprovenance,core=cprovenance,full_ct=full_ct_source,
                 report_code_sha256=sha256(Path(__file__)))
    (args.output/'SOURCES.json').write_text(json.dumps(sources,sort_keys=True,indent=2)+'\n')
    advantage_reports(args.output,ablation,core)
    dashboard(args.output,a,c,sources,args.phase5b)
    feature_context(args.output,c,args.phase5b)
    print('validated paired rows',len(ablation),len(core))


if __name__=='__main__':
    main()
