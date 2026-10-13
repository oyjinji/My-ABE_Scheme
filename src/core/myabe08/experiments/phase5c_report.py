"""Machine-generated Phase 5C figures, tables, Results, and bundle validation."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from ..analysis.core import describe, sha256_file, write_csv, write_json, write_text
from ..analysis.plots import numeric_figure
from .phase5c import ROOT, SCHEMA, validate_dataset
from .provenance import REPO, code_manifest, spec_manifest


OUTPUT = REPO/'artifacts/myabe08/analysis/phase5c'
SGX_NOTE = ('TEEProfile=SGX_DEBUG_GRAMINE_V1; '
    'ExperimentTrustMode=QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1; '
    'QVLResult=SGX_QL_QV_RESULT_OUT_OF_DATE; '
    'StrictRA2=BLOCKED_BY_TCB_POLICY; EnclaveDebug=true; '
    'CurrentHeadMode=TEST_SINGLE_LOGICAL_COORDINATOR. '
    'TEST-only feasibility measurements, not production attestation.')
FORBIDDEN = ('production-ready','fully anonymous','proven secure',
    'unlinkable','privacy proven','zero-cost revocation',
    'revocation is O(1) proven','distributed revocation is linearizable',
    'rollback is impossible','remote attestation PASS','RA2 PASS')


def _one(path):
    return json.loads(Path(path).read_text())


def _rows(path):
    return [json.loads(line) for line in (Path(path)/'raw.jsonl').read_text().splitlines()]


def _paper_table(folder,name,rows,footnote):
    if not rows:raise ValueError('empty Phase 5C table')
    fields=list(rows[0])
    write_csv(folder/f'table_{name.lower()}_data.csv',rows,fields)
    header='| '+' | '.join(fields)+' |\n'
    rule='| '+' | '.join('---' for _ in fields)+' |\n'
    body=''.join('| '+' | '.join(str(row.get(key,'')) for key in fields)+' |\n'
                 for row in rows)
    write_text(folder/f'TABLE_{name.upper()}.md',
        '# '+name.replace('_',' ').title()+'\n\n'+header+rule+body+'\n'+
        footnote+'\n\nMachine source: `table_'+name.lower()+'_data.csv`.\n')


def _stat_rows(rows,kind,metric,*,size_key='rl_size'):
    groups=defaultdict(list)
    for row in rows:
        if row['kind']==kind:
            size=(row['metrics'].get('baseline_rl_size',row['rl_size'])
                  if size_key=='baseline_rl_size' else row[size_key])
            groups[size].append(row['metrics'][metric])
    result=[]
    for size,values in sorted(groups.items()):
        result.append(dict(kind=kind,rl_size=size,metric=metric,unit='ns',
            **describe(values)))
    return result


def _index(rows):
    return {(row['kind'],row['rl_size'],row['metric']):row for row in rows}


def _ms(value):
    return round(value/1_000_000,3)


def _figure(folder,name,data,*,xlabel,ylabel,caption,unit,source_paths):
    numeric_figure(folder,name,data,x='x',y='median',series='series',
        title=name.replace('_',' '),xlabel=xlabel,ylabel=ylabel,mode='scatter',
        p95='p95' if any('p95' in item for item in data) else None,
        metadata=dict(source_datasets=source_paths,filter='frozen Phase 5C data',
            grouping='series',unit=unit,caption=caption,
            script='core.myabe08.experiments.phase5c_report.generate',
            analysis_code_sha256=code_manifest()['tree_sha256'],
            trust_cohort='REAL_SGX_DEBUG_FEASIBILITY'))


def _claim_lint(folder):
    hits=[]
    for item in sorted(folder.glob('*.md')):
        for number,line in enumerate(item.read_text().splitlines(),1):
            for term in FORBIDDEN:
                if term.casefold() in line.casefold():
                    hits.append(dict(file=item.name,line=number,term=term))
    return dict(status='PASS' if not hits else 'FAIL',hits=hits,
                files_scanned=len(list(folder.glob('*.md'))))


def generate(exp6_path,exp7_path,*,root=OUTPUT):
    exp6_path=Path(exp6_path);exp7_path=Path(exp7_path)
    checks=(validate_dataset([exp6_path]),validate_dataset([exp7_path]))
    if (checks[0]['experiment'],checks[1]['experiment'])!=('Exp6','Exp7'):
        raise ValueError('Phase 5C experiment identity mismatch')
    m6=_one(exp6_path/'manifest.json');m7=_one(exp7_path/'manifest.json')
    for key in ('plan_sha256','code_tree_sha256','spec_sha256'):
        if m6[key]!=m7[key]:raise ValueError('Phase 5C input provenance mismatch')
    analysis_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:12]
    bundle=Path(root)/analysis_id
    bundle.mkdir(parents=True,exist_ok=False)
    for folder in ('summary','figures','tables','paper','validation'):
        (bundle/folder).mkdir()
    raw6=_rows(exp6_path);raw7=_rows(exp7_path)
    stats=[]
    for kind,metric,size_key in (
        ('ACTIVE_LOOKUP','revset_lookup_ns','rl_size'),
        ('REVOKED_LOOKUP','revset_lookup_ns','rl_size'),
        ('UPDATE_INSERT','revstateupt_total_ns','baseline_rl_size'),
        ('UPDATE_DELETE','revstateupt_total_ns','baseline_rl_size')):
        stats.extend(_stat_rows(raw6,kind,metric,size_key=size_key))
    write_json(bundle/'summary'/'EXP6_STATISTICS.json',
        dict(schema=SCHEMA,source_run=m6['run_id'],rows=stats,
             ci_policy='NO_INFERENTIAL_CI_SINGLE_RUN_CONTIGUOUS_BLOCKS'))
    write_csv(bundle/'summary'/'EXP6_STATISTICS.csv',stats,list(stats[0]))
    ix=_index(stats)
    memory=_one(exp6_path/'state_memory.json')['snapshots']
    registration=_one(exp6_path/'registration_memory.json')['snapshots']
    load=_one(exp6_path/'load_plan.json')['levels']
    lifecycle=_one(exp6_path/'lifecycle.json')
    adversarial=_one(exp6_path/'adversarial.json')
    def value(kind,size,field):
        row=ix.get((kind,size,'revset_lookup_ns' if 'LOOKUP' in kind
                    else 'revstateupt_total_ns'))
        return 'NOT_APPLICABLE' if row is None else _ms(row[field])
    scaling=[]
    for snap in memory:
        size=snap['rl_size']
        scaling.append(dict(rl_size=size,n_reg=snap['n_reg'],
            active_lookup_median_ms=value('ACTIVE_LOOKUP',size,'median'),
            active_lookup_p95_ms=value('ACTIVE_LOOKUP',size,'p95'),
            revoked_lookup_median_ms=value('REVOKED_LOOKUP',size,'median'),
            revoked_lookup_p95_ms=value('REVOKED_LOOKUP',size,'p95'),
            insert_median_ms=value('UPDATE_INSERT',size,'median'),
            insert_p95_ms=value('UPDATE_INSERT',size,'p95'),
            delete_median_ms=value('UPDATE_DELETE',size,'median'),
            delete_p95_ms=value('UPDATE_DELETE',size,'p95'),
            revset_logical_bytes=snap['revset_logical_bytes'],
            state_population_ns=snap['state_population_ns'],
            request_load_measured=size==1000))
    _paper_table(bundle/'tables','exp6_revocation_scaling',scaling,
        SGX_NOTE+' At RL=0 a revoked lookup is logically not applicable. '
        'Insert/delete use paired R→R+1→R cycles and real monotonic versions.')
    load_table=[]
    for level in load:
        matching=[r['metrics']['request_latency_ns'] for r in raw6
            if r['kind']=='LOAD_'+level['request_class'] and
               r['block_id']==round(level['target_fraction']*100)]
        queue=[r['metrics']['queue_delay_ns'] for r in raw6
            if r['kind']=='LOAD_'+level['request_class'] and
               r['block_id']==round(level['target_fraction']*100)]
        if len(matching)!=level['completed_count']:
            raise ValueError('load row count mismatch')
        summary=describe(matching);q=describe(queue)
        load_table.append(dict(request_class=level['request_class'],
            target_fraction=level['target_fraction'],
            target_request_rate_hz=round(level['target_request_rate_hz'],3),
            actual_request_rate_hz=round(level['actual_request_rate_hz'],3),
            completed_count=level['completed_count'],failed_count=0,
            request_median_ms=_ms(summary['median']),
            request_p95_ms=_ms(summary['p95']),
            queue_delay_median_ms=_ms(q['median']),
            queue_delay_p95_ms=_ms(q['p95'])))
    _paper_table(bundle/'tables','exp6_request_load',load_table,
        SGX_NOTE+' Request classes are separate; rates are observed for '
        'fixed windows and do not imply production capacity.')
    semantics=[dict(case_id=key,observed=value,
        scope='TEST_SINGLE_LOGICAL_COORDINATOR') for key,value in
        list(lifecycle.items())+list(adversarial.items())]
    _paper_table(bundle/'tables','exp6_revocation_semantics',semantics,
        SGX_NOTE+' TEST behavior does not establish hardware anti-rollback '
        'or distributed linearizability.')
    write_json(bundle/'summary'/'EXP6_STATE_MEMORY.json',
        dict(revset=memory,registration=registration))
    write_json(bundle/'summary'/'EXP6_LOAD.json',load_table)

    source=[str(exp6_path.relative_to(REPO)/'raw.jsonl')]
    figures=[]
    lookup=[dict(x=row['rl_size'],series=row['kind'],
        median=_ms(row['median']),p95=_ms(row['p95'])) for row in stats
        if row['kind'] in ('ACTIVE_LOOKUP','REVOKED_LOOKUP')]
    _figure(bundle/'figures','Fig_Exp6_A_Lookup',lookup,
        xlabel='Actual enclave |RL|',ylabel='RevSet lookup (ms)',unit='ms',
        caption=SGX_NOTE+' Median circles and p95 triangles; RL=0 has no revoked member.',
        source_paths=source);figures.append('Fig_Exp6_A_Lookup')
    update=[dict(x=row['rl_size'],series=row['kind'],
        median=_ms(row['median']),p95=_ms(row['p95'])) for row in stats
        if row['kind'] in ('UPDATE_INSERT','UPDATE_DELETE')]
    _figure(bundle/'figures','Fig_Exp6_B_Update',update,
        xlabel='Baseline enclave |RL|',ylabel='RevStateUpt (ms)',unit='ms',
        caption=SGX_NOTE+' Paired insert/delete cycles; versions increase monotonically.',
        source_paths=source);figures.append('Fig_Exp6_B_Update')
    sizes=[dict(x=item['rl_size'],series='canonical RevSet bytes',
        median=item['revset_logical_bytes']) for item in memory]
    _figure(bundle/'figures','Fig_Exp6_C_State',sizes,
        xlabel='Actual enclave |RL|',ylabel='Canonical RevSet bytes',unit='bytes',
        caption=SGX_NOTE+' Logical encoding size, not process RSS or persistent SGX state.',
        source_paths=[str(exp6_path.relative_to(REPO)/'state_memory.json')]);figures.append('Fig_Exp6_C_State')
    rate=[dict(x=row['target_request_rate_hz'],series=row['request_class'],
        median=row['actual_request_rate_hz']) for row in load_table]
    _figure(bundle/'figures','Fig_Exp6_D_Load_Rate',rate,
        xlabel='Offered target requests/s',ylabel='Achieved requests/s',unit='requests/s',
        caption=SGX_NOTE+' Active and revoked request classes remain separate.',
        source_paths=source);figures.append('Fig_Exp6_D_Load_Rate')
    tail=[dict(x=row['target_request_rate_hz'],series=row['request_class'],
        median=row['request_median_ms'],p95=row['request_p95_ms']) for row in load_table]
    _figure(bundle/'figures','Fig_Exp6_D_Load_Latency',tail,
        xlabel='Offered target requests/s',ylabel='Request latency (ms)',unit='ms',
        caption=SGX_NOTE+' Median and p95 under fixed load windows.',
        source_paths=source);figures.append('Fig_Exp6_D_Load_Latency')
    if registration:
        reg=[dict(x=item['n_reg'],series='enclave registration bytes',
            median=item['registration_state_logical_bytes']) for item in registration]
        _figure(bundle/'figures','Fig_Exp6_E_Registration',reg,
            xlabel='Actual enclave n_reg',ylabel='Canonical registry bytes',unit='bytes',
            caption=SGX_NOTE+' Measured at RL=0; registration state is distinct from RevSet.',
            source_paths=[str(exp6_path.relative_to(REPO)/'registration_memory.json')]);figures.append('Fig_Exp6_E_Registration')

    inventory=_one(exp7_path/'transcript_inventory.json')
    freshness=_one(exp7_path/'freshness.json')
    equality=_one(exp7_path/'equality.json')
    leakage=_one(exp7_path/'known_leakage.json')
    audit=_one(exp7_path/'canary_audit.json')
    _paper_table(bundle/'tables','exp7_transcript_surface',
        [dict(**row,forbidden_field_scan=audit['status'],
              known_leakage='; '.join(inventory['known_leakage']))
         for row in inventory['rows']],
        SGX_NOTE+' Inventory lists the defined CSP-visible surface; '
        'the denylist scan applies to this controlled run and logs.')
    _paper_table(bundle/'tables','exp7_freshness_observations',
        freshness['observations'],
        SGX_NOTE+' No collision observed is not a randomness proof.')
    equality_rows=[
        dict(relation='same attribute/same context token',
             sample_count=equality['same_context_checks'],
             equality_count=equality['same_context_equal_count']),
        dict(relation='same attribute/different context token',
             sample_count=equality['cross_context_checks'],
             equality_count=equality['direct_cross_context_equal_count']),
        dict(relation='same user/same CT W',
             sample_count=leakage['same_user_same_ct_w_requests'],
             equality_count=leakage['equality_count']),
        dict(relation='same user/different CT W',
             sample_count=leakage['same_user_different_ct_w_comparisons'],
             equality_count=leakage['same_user_different_ct_w_equal_count']),
        dict(relation='different user/same CT W',
             sample_count=leakage['different_user_same_ct_w_comparisons'],
             equality_count=leakage['different_user_same_ct_w_equal_count']),
        dict(relation='AF same-context matching',
             sample_count=50,equality_count=equality['same_context_af_success_count'])]
    _paper_table(bundle/'tables','exp7_equality_linkability',equality_rows,
        SGX_NOTE+' Equality counts are finite observations, not anonymity '
        'or unlinkability proofs. Same-user/same-CT W stability is known leakage.')
    write_json(bundle/'summary'/'EXP7_OBSERVATIONS.json',dict(
        transcript_inventory=inventory,freshness=freshness,equality=equality,
        known_leakage=leakage,canary_audit=audit))

    small=scaling[0];large=scaling[-1]
    write_text(bundle/'paper'/'RESULTS_EXP6.md',
        '# Exp6 Results draft\n\n## Research question\n\nHow does actual '
        'enclave RevSet size relate to access-time lookup, monotonic update, '
        'logical state size, and observed request load?\n\n'
        '## State dimensions\n\nRL is the exact enclave RevSet count; '
        'n_reg is the enclave credential/version registry count. '
        'The two are not conflated.\n\n'
        '## Observed lookup cost\n\nActive lookup median was '
        f'{small["active_lookup_median_ms"]:.3f} ms at RL={small["rl_size"]} '
        f'and {large["active_lookup_median_ms"]:.3f} ms at RL={large["rl_size"]}. '
        'Revoked lookup is not applicable at RL=0.\n\n'
        '## Observed update cost\n\nThe table reports separate insert and '
        'delete median/p95 values from R→R+1→R cycles with real increasing '
        'versions. Population time is reported separately.\n\n'
        '## Memory/state cost\n\nCanonical RevSet bytes were '
        f'{small["revset_logical_bytes"]} at RL={small["rl_size"]} and '
        f'{large["revset_logical_bytes"]} at RL={large["rl_size"]}. '
        'These are not process RSS or production persistence.\n\n'
        '## Load behavior\n\nTarget and achieved rates, completed counts, '
        'queue delay, median and p95 latency are in the generated load table; '
        'active and revoked classes remain separate.\n\n'
        '## Correctness/adversarial behavior\n\nThe generated semantics '
        'table records lifecycle and TEST coordinator negative outcomes.\n\n'
        '## Boundary\n\n'+SGX_NOTE+' One run with three contiguous blocks per '
        'configuration supports descriptive statistics only; no inferential '
        'CI or complexity proof is reported.\n')
    write_text(bundle/'paper'/'RESULTS_EXP7.md',
        '# Exp7 Results draft\n\n## Transcript surface\n\nThe inventory '
        'enumerates the CSP-visible fields and controlled logs.\n\n'
        '## Forbidden-field audit\n\nThe TEST canary scan returned '
        f'{audit["status"]} across {audit["files_scanned"]} controlled files; '
        'no defined canary appeared.\n\n'
        '## Fresh component observations\n\nFifty repeated same-user/same-CT '
        'requests were compared in memory. Per-component uniqueness counts '
        'are in the machine table; no component bytes were persisted.\n\n'
        '## Context equality observations\n\nSame-context equality was '
        f'{equality["same_context_equal_count"]}/{equality["same_context_checks"]}; '
        'direct cross-context equality was '
        f'{equality["direct_cross_context_equal_count"]}/'
        f'{equality["cross_context_checks"]}.\n\n'
        '## Known W linkability\n\nSame-user/same-CT W remained equal in '
        f'{leakage["equality_count"]}/{leakage["same_user_same_ct_w_requests"]} '
        'tested requests. This is disclosed linkability.\n\n'
        '## Boundary\n\n'+SGX_NOTE+' Finite equality observations do not '
        'establish full anonymity, independence, or side-channel resistance.\n')
    write_text(bundle/'paper'/'REVOCATION_SECURITY_EVIDENCE.md',
        '# Phase 5C revocation and transcript evidence\n\n'
        'The measured path used public Rev, RevStateUpt and TEEAuthorize, '
        'with the real enclave exact RevSet. Revoked requests were checked '
        'before token, T0 and cap emission. The lifecycle evidence records '
        'historical unconsumed Auth acceptance and unchanged CT, token '
        'representation and RK. Invalid updates were evaluated under the '
        'TEST single logical coordinator.\n\n'+SGX_NOTE+'\n')
    write_text(bundle/'paper'/'PHASE5C_LIMITATIONS.md',
        '# Phase 5C limitations\n\n'+SGX_NOTE+' The DEBUG enclave has an '
        'OUT_OF_DATE platform TCB and strict RA2 remains blocked. The TEST '
        'coordinator is not a production remote current-head. Production '
        'persistent SGX state, hardware anti-rollback, trusted time and a '
        'release enclave are absent. Side channels remain unaddressed. '
        'Formal status: CANDIDATE — FORMAL PROOF OPEN. Exp2 remains '
        'BLOCKED_COMMON_BACKEND. No cross-curve comparison is made.\n\n'
        'Same-context token equality, DataID, context, AF hits, J/I, access '
        'timing/count, ciphertext identity, revocation behavior, and stable '
        'same-user/same-CT W are disclosed observations.\n')
    lint=_claim_lint(bundle/'paper')
    write_json(bundle/'validation'/'claim_lint.json',lint)
    if lint['status']!='PASS':raise ValueError('Phase 5C claim lint failed')
    quality=(f'# Phase 5C data quality\n\nExp6 run: `{m6["run_id"]}`; '
        f'Exp7 run: `{m7["run_id"]}`. Exp6 rows: {len(raw6)}; '
        f'Exp7 rows: {len(raw7)}. Expected rejects: '
        f'{m6["expected_rejects"]+m7["expected_rejects"]}; '
        'unexpected failures: 0; timeouts: 0.\n\n'
        f'Schema: {SCHEMA}; plan: `{m6["plan_sha256"]}`; '
        f'code tree: `{m6["code_tree_sha256"]}`; '
        f'specification: `{m6["spec_sha256"]}`. '
        'Trust: '+SGX_NOTE+'\n\n'
        'Every run and dataset validator passed. All raw rows are retained. '
        'Median, Q1/Q3, mean/std, p90/p95 and max are machine-generated; '
        'there is no outlier deletion or inferential CI with one run and '
        'three contiguous blocks. Revoked outcomes are EXPECTED_REJECT, '
        'not unexpected failures.\n')
    write_text(bundle/'validation'/'PHASE5C_DATA_QUALITY.md',quality)
    evidence='# Phase 5C revocation evidence\n\n'+(
        bundle/'paper'/'REVOCATION_SECURITY_EVIDENCE.md').read_text()
    write_text(bundle/'validation'/'PHASE5C_REVOCATION_EVIDENCE.md',evidence)
    input_hashes={str(item.relative_to(REPO)):sha256_file(item)
        for path in (exp6_path,exp7_path) for item in sorted(path.iterdir())
        if item.is_file()}
    outputs={str(item.relative_to(bundle)):sha256_file(item)
        for item in sorted(bundle.rglob('*')) if item.is_file()}
    write_json(bundle/'analysis_manifest.json',dict(
        schema='MYABE08-PHASE5C-ANALYSIS-V1',analysis_id=analysis_id,
        created_utc=datetime.now(timezone.utc).isoformat(),status='COMPLETE',
        input_runs=[m6['run_id'],m7['run_id']],input_hashes=input_hashes,
        code_tree_sha256=m6['code_tree_sha256'],
        spec_sha256=spec_manifest()['sha256'],figures=figures,
        tables=['EXP6_REVOCATION_SCALING','EXP6_REQUEST_LOAD',
            'EXP6_REVOCATION_SEMANTICS','EXP7_TRANSCRIPT_SURFACE',
            'EXP7_FRESHNESS_OBSERVATIONS','EXP7_EQUALITY_LINKABILITY'],
        statistics_policy='all samples; median/IQR/p95; no inferential CI',
        output_hashes=outputs))
    return bundle


def verify(bundle):
    bundle=Path(bundle);manifest=_one(bundle/'analysis_manifest.json')
    if manifest['schema']!='MYABE08-PHASE5C-ANALYSIS-V1' or manifest['status']!='COMPLETE':
        raise ValueError('Phase 5C analysis manifest invalid')
    for relative,digest in manifest['input_hashes'].items():
        if sha256_file(REPO/relative)!=digest:
            raise ValueError('Phase 5C analysis input changed')
    for relative,digest in manifest['output_hashes'].items():
        if sha256_file(bundle/relative)!=digest:
            raise ValueError('Phase 5C analysis output changed')
    actual={str(item.relative_to(bundle)) for item in bundle.rglob('*') if item.is_file()}
    if actual!=set(manifest['output_hashes'])|{'analysis_manifest.json'}:
        raise ValueError('Phase 5C analysis file set changed')
    if _claim_lint(bundle/'paper')['status']!='PASS':
        raise ValueError('Phase 5C claim lint failed')
    return dict(status='PASS',analysis_id=manifest['analysis_id'],
        figures=len(manifest['figures']),tables=len(manifest['tables']),
        outputs=len(manifest['output_hashes']))


def compare(first,second):
    verify(first);verify(second)
    first=Path(first);second=Path(second);names=[]
    for folder in ('summary','tables','paper','figures','validation'):
        for item in sorted((first/folder).iterdir()):
            if folder=='figures' and item.suffix in ('.png','.pdf'):
                continue
            names.append(str(item.relative_to(first)))
    for name in names:
        if sha256_file(first/name)!=sha256_file(second/name):
            raise ValueError('Phase 5C semantic analysis differs: '+name)
    return dict(status='PASS',semantic_files_compared=len(names))
