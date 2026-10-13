"""Machine summaries, figures and paper tables from validated raw rows."""
from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import statistics

from . import ANALYSIS_SCHEMA
from .core import (COHORTS, REPO, analysis_code_hash, statistics_rows,
                   write_csv, write_json, write_text)
from .plots import numeric_figure, bar_figure, distribution_figure


SGX = 'SGX_DEBUG_GRAMINE_V1'
EMU = 'EMULATED_TEE_PROFILE'
SGX_NOTE = ('TEEProfile=SGX_DEBUG_GRAMINE_V1; '
    'ExperimentTrustMode=QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1. '
    'Gramine SGX DEBUG feasibility: QVL completed with '
    'SGX_QL_QV_RESULT_OUT_OF_DATE; strict RA2 remains BLOCKED_BY_TCB_POLICY. '
    'These are not production-attested measurements.')


def _metric(records: list[dict], metric: str) -> list[dict]:
    return [row for row in records if row['metric'] == metric]


def _lookup(records: list[dict]) -> dict:
    return {(row['configuration_id'], row['metric']): row for row in records}


def _ms(ns) -> float:
    return round(float(ns) / 1_000_000, 3)


def _fig_rows(records: list[dict], metric: str, *, x: str, series: str,
              milliseconds=True) -> list[dict]:
    rows = []
    for record in _metric(records, metric):
        factor = 1_000_000 if milliseconds else 1
        rows.append(dict(configuration_id=record['configuration_id'],
            run_id=record['run_id'], sample_ids=json.dumps(record['sample_ids']),
            dataset_manifest_sha256=record['dataset_manifest_sha256'],
            backend=record['backend'], trust_cohort=record['trust_cohort'],
            x=record[x], series=str(record[series]),
            median=record['median']/factor, p95=record['p95']/factor,
            n=record['n'], metric=metric,
            ell=record['ell'], N=record['N'], cmax=record['cmax'],
            actual_J=record['actual_J'], requested_J=record['requested_J'],
            actual_tI=record['actual_tI'], actual_k=record['actual_k'],
            policy_shape=record['policy_shape']))
    return rows


def _metadata(experiment: str, cohorts: list[dict], code_hash: str,
              caption: str, grouping: str, unit: str, filter_text='all frozen configurations') -> dict:
    return dict(source_datasets=[c['manifest_sha256'] for c in cohorts],
        source_dataset_manifests=[str((c['directory']/'dataset_manifest.json').relative_to(REPO))
                                  for c in cohorts],
        experiment=experiment, filter=filter_text, grouping=grouping,
        unit=unit, caption=caption, analysis_code_sha256=code_hash,
        script='core.myabe08.analysis.products.produce_figures',
        trust_cohorts=[c['dataset']['trust_cohort'] for c in cohorts])


def _line(directory, name, data, *, x_label, y_label, mode, metadata,
          show_p95=True):
    numeric_figure(directory, name, data, x='x', y='median',
        title=name.replace('_',' '), xlabel=x_label, ylabel=y_label,
        series='series', mode=mode,
        p95='p95' if show_p95 else None, metadata=metadata)


def _table(path: Path, name: str, rows: list[dict], fields: list[str],
           footnote: str) -> None:
    if not rows:
        raise ValueError('empty paper table')
    write_csv(path / f'table_{name}_data.csv', rows, fields)
    header = '| ' + ' | '.join(fields) + ' |\n'
    divider = '| ' + ' | '.join('---' for _ in fields) + ' |\n'
    body = ''.join('| ' + ' | '.join(str(row.get(field,'')) for field in fields)
                   + ' |\n' for row in rows)
    write_text(path / f'TABLE_{name.upper()}.md',
        '# ' + name.replace('_',' ').title() + '\n\n' + header + divider + body +
        '\n' + footnote + '\n\nNumeric cells are generated from the linked '
        '`table_' + name + '_data.csv`; configuration and run IDs trace to raw JSONL.\n')


def produce_summaries(bundle: Path, loaded: dict, code_hash: str) -> dict:
    summaries = {}
    for (experiment, backend), cohort in loaded['cohorts'].items():
        records = statistics_rows(cohort, experiment, backend)
        for record in records:
            record['analysis_code_sha256'] = code_hash
        summaries[(experiment, backend)] = records
    names = {'Exp1':'EXP1_STATISTICS', 'Exp3':'EXP3_STORAGE',
             'Exp4':'EXP4_STATISTICS', 'Exp5':'EXP5_STATISTICS'}
    for experiment, stem in names.items():
        rows = [row for key in COHORTS if key[0] == experiment
                for row in summaries[key]]
        write_json(bundle/'summary'/f'{stem}.json',
            dict(analysis_schema=ANALYSIS_SCHEMA, analysis_code_sha256=code_hash,
                 experiment=experiment, rows=rows,
                 ci_policy='NO_INFERENTIAL_CI_ONE_RUN_THREE_BLOCKS'))
        fields = ['analysis_schema','analysis_code_sha256',
                  'dataset_manifest_sha256','experiment','backend','trust_cohort',
                  'configuration_id','run_id','sample_ids','ell','N','cmax',
                  'repeat_regime','policy_shape','requested_L_hit','actual_L_hit',
                  'requested_J','actual_J','actual_k','actual_tI',
                  'occurrence_slot_count','metric','unit','n','min','q1',
                  'median','q3','mean','std','p90','p95','max']
        csv_rows = [dict(row, sample_ids=json.dumps(row['sample_ids'],
                         separators=(',', ':'))) for row in rows]
        write_csv(bundle/'summary'/f'{stem}.csv', csv_rows, fields)
    exp5_rows = [row for row in summaries[('Exp5',SGX)]
                 if row['metric']=='request_e2e_ns']
    difference = [dict(configuration_id=row['configuration_id'],
        run_id=row['run_id'],requested_J=row['requested_J'],
        actual_J=row['actual_J'],difference=row['requested_J']-row['actual_J'],
        sample_count=row['n'],dataset_manifest_sha256=row['dataset_manifest_sha256'])
        for row in exp5_rows]
    difference.sort(key=lambda row: row['configuration_id'])
    write_csv(bundle/'summary'/'EXP5_REQUESTED_ACTUAL_J.csv',difference,
        list(difference[0]))
    write_json(bundle/'summary'/'EXP5_REQUESTED_ACTUAL_J.json',
        dict(analysis_schema=ANALYSIS_SCHEMA,rows=difference,
             differing_sample_count=sum(r['sample_count'] for r in difference
                                        if r['difference']!=0)))
    return summaries


def produce_tables(bundle: Path, loaded: dict, summaries: dict) -> dict:
    path = bundle/'tables'; out = {}
    env_rows = []
    for backend in (EMU, SGX):
        cohort = loaded['cohorts'][('Exp4', backend)]
        first_run = cohort['directory']/cohort['run_ids'][0]
        environment = json.loads((first_run/'environment.json').read_text())
        env_rows.append(dict(backend=backend, cpu=environment['cpu']['model_name'],
            os=environment['os_release']['PRETTY_NAME'],
            python=environment['python']['version'],
            gramine=environment['sgx']['gramine_version'] if backend == SGX else 'N/A',
            curve=environment['pairing']['curve'],
            tee_profile=backend,
            trust_mode=cohort['dataset']['trust_cohort'],
            qvl_result='SGX_QL_QV_RESULT_OUT_OF_DATE' if backend == SGX else 'N/A',
            warmups=5, measured_repetitions=20,
            environment_fingerprint=cohort['dataset']['environment_fingerprint']))
    fields = list(env_rows[0])
    _table(path,'environment_profile',env_rows,fields,SGX_NOTE)
    out['environment_profile'] = env_rows

    exp1 = summaries[('Exp1',SGX)]; index = _lookup(exp1)
    rows = []
    for anchor in _metric(exp1,'encrypt_ns'):
        cid=anchor['configuration_id']; get=lambda name:index[(cid,name)]
        rows.append(dict(configuration_id=cid,run_id=anchor['run_id'],
            ell=anchor['ell'],repeat_regime=anchor['repeat_regime'],
            k=anchor['actual_k'],cmax=anchor['cmax'],tI=anchor['actual_tI'],
            actual_D_j_count=anchor['cmax'],
            analytical_per_row_D_reference=anchor['ell'],
            analytical_count_difference=anchor['ell']-anchor['cmax'],
            CT_bytes=round(get('ct_total_bytes')['median']),
            CT_core_bytes=round(get('ct_core_bytes')['median']),
            Encrypt_median_ms=_ms(get('encrypt_ns')['median']),
            Encrypt_p95_ms=_ms(get('encrypt_ns')['p95']),
            Transform_median_ms=_ms(get('transform_ns')['median']),
            Transform_p95_ms=_ms(get('transform_ns')['p95']),
            TEE_pairings=round(get('tee_pairing_count')['median']),
            CSP_pairings=round(get('csp_pairing_count')['median']),
            system_pairings=round(get('system_pairing_count')['median'])))
    rows.sort(key=lambda r:(r['ell'],r['cmax']))
    _table(path,'exp1_results',rows,list(rows[0]),SGX_NOTE+
        ' Per-row D reference is analytical component counting only; it was not benchmarked as an implementation or timing baseline.')
    out['exp1_results']=rows

    exp3 = summaries[('Exp3',EMU)]; index=_lookup(exp3); rows=[]
    for anchor in _metric(exp3,'ct_total_bytes'):
        cid=anchor['configuration_id']; get=lambda name:round(index[(cid,name)]['median'])
        width=4*(anchor['cmax']+1)+16
        slot_bytes=get('af_slot_bytes')
        if slot_bytes % width:
            raise ValueError('AF slot bytes do not match frozen slot width')
        parts=[get(x) for x in ('ct_core_bytes','af_total_bytes','header_bytes',
                                'dem_bytes','publication_bytes')]
        if sum(parts)!=get('ct_total_bytes'):
            raise ValueError('nonexclusive CT storage breakdown')
        rows.append(dict(configuration_id=cid,run_id=anchor['run_id'],
            ell=anchor['ell'],cmax=anchor['cmax'],
            CT_total_bytes=get('ct_total_bytes'),CT_core_bytes=parts[0],
            AF_bytes=parts[1],AF_slot_count=slot_bytes//width,
            AF_slot_width_bytes=width,header_bytes=parts[2],DEM_bytes=parts[3],
            publication_bytes=parts[4],credential_bytes=get('credential_bytes'),
            sealed_blob_bytes=get('sealed_blob_bytes'),Auth_bytes=get('auth_bytes'),
            CT_prime_bytes=get('ctprime_bytes'),
            revocation_CT_components=0,public_KU=0,tree_TK=0))
    rows.sort(key=lambda r:(r['ell'],r['cmax']))
    _table(path,'exp3_storage',rows,list(rows[0]),
        'Canonical byte accounting; the five CT categories are mutually exclusive '
        'and sum to CT total. Revocation CT components, public KU and tree TK are '
        'not present in the current construction. EMULATED_TEST only.')
    out['exp3_storage']=rows

    rows=[]
    for backend in (EMU,SGX):
        records=summaries[('Exp4',backend)]; index=_lookup(records)
        for anchor in _metric(records,'policy_token_ns'):
            cid=anchor['configuration_id'];get=lambda name:index.get((cid,name))
            def val(name,stat):
                item=get(name)
                return _ms(item[stat]) if item else 'NOT_OBSERVED'
            rows.append(dict(configuration_id=cid,run_id=anchor['run_id'],
                backend=backend,N=anchor['N'],ell=anchor['ell'],cmax=anchor['cmax'],
                batch_policy=anchor['ell'],batch_user=anchor['N'],
                actual_L_hit=anchor['actual_L_hit'],
                policy_token_median_ms=val('policy_token_ns','median'),
                policy_token_p95_ms=val('policy_token_ns','p95'),
                user_token_median_ms=val('user_token_ns','median'),
                user_token_p95_ms=val('user_token_ns','p95'),
                AF_query_median_ms=val('af_query_ns','median'),
                AF_query_p95_ms=val('af_query_ns','p95'),
                host_to_TEE_bytes=round(get('host_to_tee_bytes')['median']) if get('host_to_tee_bytes') else 'NOT_OBSERVED',
                TEE_to_host_bytes=round(get('tee_to_host_bytes')['median']) if get('tee_to_host_bytes') else 'NOT_OBSERVED',
                RPC_roundtrip_median_ms=val('rpc_roundtrip_ns','median')))
    rows.sort(key=lambda r:(r['backend'],r['ell'],r['cmax'],r['actual_L_hit']))
    _table(path,'exp4_token_af',rows,list(rows[0]),
        SGX_NOTE + ' Real/EMULATED ratios are observed deployment-profile ratios, '
        'not isolated hardware overhead. RPC receive overlaps enclave work.')
    out['exp4_token_af']=rows

    exp5=summaries[('Exp5',SGX)];index=_lookup(exp5);rows=[]
    for anchor in _metric(exp5,'request_e2e_ns'):
        cid=anchor['configuration_id'];get=lambda name:index[(cid,name)]
        rows.append(dict(configuration_id=cid,run_id=anchor['run_id'],
            policy_shape=anchor['policy_shape'],N=anchor['N'],ell=anchor['ell'],
            requested_J=anchor['requested_J'],actual_J=anchor['actual_J'],
            k=anchor['actual_k'],tI=anchor['actual_tI'],
            AF_query_median_ms=_ms(get('af_query_ns')['median']),
            AuthorizedSubset_median_ms=_ms(get('authorized_subset_ns')['median']),
            TEEAuthorize_median_ms=_ms(get('tee_authorize_ns')['median']),
            Transform_median_ms=_ms(get('transform_ns')['median']),
            Transform_p95_ms=_ms(get('transform_ns')['p95']),
            E2E_median_ms=_ms(anchor['median']),E2E_p95_ms=_ms(anchor['p95']),
            CSP_pairings=round(get('csp_pairing_count')['median'])))
    rows.sort(key=lambda r:(r['policy_shape'],r['N'],r['actual_J']))
    _table(path,'exp5_scaling',rows,list(rows[0]),
        SGX_NOTE + ' Main candidate and reconstruction axes use actual J and tI.')
    out['exp5_scaling']=rows
    return out


def produce_figures(bundle: Path, loaded: dict, summaries: dict,
                    code_hash: str) -> list[str]:
    directory=bundle/'figures'; ids=[]
    def line(name, records, metric, *, experiment, cohorts, x, series,
             xlabel, ylabel, mode='line', millis=True, caption='',
             filter_text='all frozen configurations', p95=True, unit=None):
        data=_fig_rows(records,metric,x=x,series=series,milliseconds=millis)
        meta=_metadata(experiment,cohorts,code_hash,caption,series,
                       unit or ('ms' if millis else
                           ('bytes' if metric.endswith('bytes') else 'count')),
                       filter_text)
        _line(directory,name,data,x_label=xlabel,y_label=ylabel,mode=mode,
              metadata=meta,show_p95=p95)
        ids.append(name)

    e1=loaded['cohorts'][('Exp1',SGX)];s1=summaries[('Exp1',SGX)]
    line('Fig_Exp1_A_Encrypt',s1,'encrypt_ns',experiment='Exp1',cohorts=[e1],
         x='ell',series='repeat_regime',xlabel='Policy rows ell',ylabel='Encrypt latency (ms)',
         caption=SGX_NOTE+' Median and p95 by repeat regime; each configuration has n=20.')
    line('Fig_Exp1_B_Transform',s1,'transform_ns',experiment='Exp1',cohorts=[e1],
         x='ell',series='repeat_regime',xlabel='Policy rows ell',ylabel='Transform latency (ms)',
         caption=SGX_NOTE+' Median and p95; changes in J and tI also vary by regime.')
    line('Fig_Exp1_C_CT_Core',s1,'ct_core_bytes',experiment='Exp1',cohorts=[e1],
         x='ell',series='cmax',xlabel='Policy rows ell',ylabel='Canonical CT core (bytes)',
         millis=False,p95=False,caption=SGX_NOTE+' Canonical CT core; cmax varies by repeat regime.')
    pairs=[]
    for t_i in sorted({r['actual_tI'] for r in _metric(s1,'csp_pairing_count')}):
        source=[r for r in _metric(s1,'csp_pairing_count') if r['actual_tI']==t_i]
        observed={r['median'] for r in source}
        if observed!={1+t_i}:raise ValueError('Exp1 pairing invariant failed')
        for series in ('observed CSP','analytical 1+tI'):
            pairs.append(dict(x=t_i,median=1+t_i,p95=1+t_i,series=series,
                actual_tI=t_i,trust_cohort=e1['dataset']['trust_cohort'],
                dataset_manifest_sha256=e1['manifest_sha256'],
                source_configuration_ids=json.dumps(sorted(r['configuration_id'] for r in source))))
    _line(directory,'Fig_Exp1_D_Pairings',pairs,x_label='Actual tI',
          y_label='CSP pairing count',mode='line',show_p95=False,
          metadata=_metadata('Exp1',[e1],code_hash,
              SGX_NOTE+' Operation count, not a timing baseline.',
              'actual_tI','count'))
    ids.append('Fig_Exp1_D_Pairings')
    distribution=[]
    for r in e1['rows']:
        if r['variables']['ell']==20:
            distribution.append(dict(repeat_regime=r['variables']['repeat_regime'],
                value_ms=r['metrics']['transform_ns']/1_000_000,
                sample_id=r['sample_id'],configuration_id=r['configuration_id'],
                run_id=r['run_id'],dataset_manifest_sha256=e1['manifest_sha256']))
    distribution_figure(directory,'Fig_Exp1_E_Distribution',distribution,
        group='repeat_regime',value='value_ms',title='Exp1 Transform distribution at ell=20',
        ylabel='Transform latency (ms)',
        metadata=_metadata('Exp1',[e1],code_hash,
            SGX_NOTE+' All 80 raw samples, including whisker-exterior points, are shown.',
            'repeat_regime','ms','ell=20; all repeat regimes'))
    ids.append('Fig_Exp1_E_Distribution')

    e3=loaded['cohorts'][('Exp3',EMU)];s3=summaries[('Exp3',EMU)]
    line('Fig_Exp3_A_Storage',s3,'ct_total_bytes',experiment='Exp3',cohorts=[e3],
         x='ell',series='cmax',xlabel='Policy rows ell',ylabel='Canonical CT total (bytes)',
         millis=False,p95=False,
         caption='EMULATED_TEST canonical byte accounting; one artifact per configuration.')
    storage_index=_lookup(s3);storage=[]
    for anchor in _metric(s3,'ct_total_bytes'):
        if anchor['ell']!=40:continue
        cid=anchor['configuration_id']
        for component,metric in (('CT core','ct_core_bytes'),('AF','af_total_bytes'),
                                  ('header','header_bytes'),('DEM','dem_bytes'),
                                  ('publication','publication_bytes')):
            storage.append(dict(cmax=anchor['cmax'],component=component,
                bytes=storage_index[(cid,metric)]['median'],configuration_id=cid,
                dataset_manifest_sha256=e3['manifest_sha256']))
    storage.sort(key=lambda row: row['cmax'])
    bar_figure(directory,'Fig_Exp3_B_Breakdown',storage,label='cmax',value='bytes',
        title='Exp3 canonical CT breakdown at ell=40',ylabel='Bytes',stack=True,
        metadata=dict(_metadata('Exp3',[e3],code_hash,
            'EMULATED_TEST. Five mutually exclusive categories sum to CT total; ell=40 is a representative slice.',
            'cmax','bytes','ell=40; cmax=1..5'),statistic='canonical bytes'))
    ids.append('Fig_Exp3_B_Breakdown')

    e4a=loaded['cohorts'][('Exp4',EMU)];e4b=loaded['cohorts'][('Exp4',SGX)]
    s4=summaries[('Exp4',EMU)]+summaries[('Exp4',SGX)]
    for name,metric,x,xlabel,ylabel,millis in (
        ('Fig_Exp4_A_Policy_Token','policy_token_ns','ell','Policy token batch size','Policy tokenization (ms)',True),
        ('Fig_Exp4_B_User_Token','user_token_ns','N','User token batch size','User tokenization (ms)',True),
        ('Fig_Exp4_C_Policy_Throughput','policy_token_ops_per_s','ell','Policy token batch size','Policy token throughput (ops/s)',False),
        ('Fig_Exp4_D_User_Throughput','user_token_ops_per_s','N','User token batch size','User token throughput (ops/s)',False),
        ('Fig_Exp4_E_AF_Build','af_build_ns','ell','Policy rows ell','AF.Build latency (ms)',True),
        ('Fig_Exp4_F_AF_Query','af_query_ns','actual_L_hit','Actual L_hit','AF.Query latency (ms)',True)):
        line(name,s4,metric,experiment='Exp4',cohorts=[e4a,e4b],
            x=x,series='backend',xlabel=xlabel,ylabel=ylabel,mode='scatter',
            millis=millis,p95=millis,
            unit='ops/s' if not millis else 'ms',
            caption=SGX_NOTE+' EMULATED_TEST and real SGX are separate series. '
                    'Other structural variables vary across the selected grid; points are descriptive.')
    for backend, cohort, figure_id in (
        (EMU, e4a, 'Fig_Exp4_I_Emulated_Distribution'),
        (SGX, e4b, 'Fig_Exp4_J_SGX_Distribution')):
        selected_raw=[r for r in cohort['rows'] if
            r['variables']['ell']==20 and r['variables']['N']==20 and
            r['variables']['cmax']==2 and
            r['variables']['requested_L_hit']=='HIGH']
        if len(selected_raw)!=20:
            raise ValueError('Exp4 backend distribution configuration absent')
        distribution=[dict(backend=backend,
            value_ms=r['metrics']['policy_token_ns']/1_000_000,
            sample_id=r['sample_id'],configuration_id=r['configuration_id'],
            run_id=r['run_id'],dataset_manifest_sha256=cohort['manifest_sha256'])
            for r in selected_raw]
        distribution_figure(directory,figure_id,distribution,group='backend',
            value='value_ms',title=f'Exp4 policy-token distribution: {backend}',
            ylabel='Policy tokenization latency (ms)',
            metadata=_metadata('Exp4',[cohort],code_hash,
                (SGX_NOTE if backend==SGX else 'EMULATED_TEST. ')+
                'All 20 raw samples, including whisker-exterior points, are shown.',
                'backend','ms','ell=20,N=20,cmax=2,HIGH hit; n=20'))
        ids.append(figure_id)
    selected=[r for r in e4b['rows'] if r['variables']['ell']==20 and
              r['variables']['N']==20 and r['variables']['cmax']==2 and
              r['variables']['requested_L_hit']=='HIGH']
    if len(selected)!=20:raise ValueError('Exp4 representative configuration absent')
    rpc_fields=(('host pre-RPC','host_pre_rpc_ns'),('RPC send','rpc_send_ns'),
                ('enclave total','enclave_total_ns'),('RPC receive','rpc_receive_ns'),
                ('host post-RPC','host_post_rpc_ns'))
    rpc=[dict(stage=name,median_ms=statistics.median(r['metrics'][key] for r in selected)/1_000_000,
              configuration_id=selected[0]['configuration_id'],
              dataset_manifest_sha256=e4b['manifest_sha256']) for name,key in rpc_fields]
    bar_figure(directory,'Fig_Exp4_G_RPC_Breakdown',rpc,label='stage',
        value='median_ms',title='Exp4 real SGX RPC observations',ylabel='Median duration (ms)',
        metadata=dict(_metadata('Exp4',[e4b],code_hash,
            SGX_NOTE+' Log-scale y axis. RPC receive overlaps enclave execution. Bars are separate observations, not additive components.',
            'stage','ms','ell=20,N=20,cmax=2,HIGH hit; n=20'),statistic='median'),
        log_scale=True)
    ids.append('Fig_Exp4_G_RPC_Breakdown')
    inner=(('credential verify','credential_verify_ns'),('RevSet lookup','revset_lookup_ns'),
           ('tokenization','tokenization_ns'),('rerandomization','rerandomization_ns'),
           ('T0 pairing','t0_pairing_ns'),('cap signing','cap_sign_ns'))
    residuals=[]
    for r in selected:
        residual=r['metrics']['enclave_total_ns']-sum(r['metrics'][key] for _,key in inner)
        if residual<0:raise ValueError('negative enclave unattributed duration')
        residuals.append(residual)
    enclave=[dict(slice='representative',component=name,
                  mean_ms=statistics.mean(r['metrics'][key] for r in selected)/1_000_000,
                  configuration_id=selected[0]['configuration_id'],
                  dataset_manifest_sha256=e4b['manifest_sha256']) for name,key in inner]
    enclave.append(dict(slice='representative',component='unattributed overhead',
        mean_ms=statistics.mean(residuals)/1_000_000,
        configuration_id=selected[0]['configuration_id'],
        dataset_manifest_sha256=e4b['manifest_sha256']))
    bar_figure(directory,'Fig_Exp4_H_Enclave_Stages',enclave,label='slice',
        value='mean_ms',title='Exp4 real SGX enclave stages',ylabel='Mean duration (ms)',
        stack=True,metadata=dict(_metadata('Exp4',[e4b],code_hash,
            SGX_NOTE+' Mutually exclusive measured stages plus unattributed overhead; means are used only for additive accounting.',
            'stage','ms','ell=20,N=20,cmax=2,HIGH hit; n=20'),statistic='mean additive accounting'))
    ids.append('Fig_Exp4_H_Enclave_Stages')

    e5=loaded['cohorts'][('Exp5',SGX)];s5=summaries[('Exp5',SGX)]
    for name,metric,x,xlabel,ylabel in (
        ('Fig_Exp5_A_AF_Query','af_query_ns','actual_J','Actual |J|','AF.Query latency (ms)'),
        ('Fig_Exp5_B_AuthorizedSubset','authorized_subset_ns','actual_J','Actual |J|','AuthorizedSubset latency (ms)'),
        ('Fig_Exp5_C_Transform','transform_ns','actual_tI','Actual tI','Transform latency (ms)'),
        ('Fig_Exp5_E_E2E','request_e2e_ns','N','Registered population N','Request E2E latency (ms)')):
        line(name,s5,metric,experiment='Exp5',cohorts=[e5],x=x,
            series='policy_shape',xlabel=xlabel,ylabel=ylabel,mode='scatter',
            caption=SGX_NOTE+' Points are configuration medians; candidate axes use actual values.')
    pair=[]
    for t_i in sorted({r['actual_tI'] for r in _metric(s5,'csp_pairing_count')}):
        source=[r for r in _metric(s5,'csp_pairing_count') if r['actual_tI']==t_i]
        observed={r['median'] for r in source}
        if observed!={1+t_i}:raise ValueError('Exp5 pairing invariant failed')
        for series in ('observed CSP','analytical 1+tI'):
            pair.append(dict(x=t_i,median=1+t_i,p95=1+t_i,series=series,
                actual_tI=t_i,dataset_manifest_sha256=e5['manifest_sha256'],
                source_configuration_ids=json.dumps(sorted(r['configuration_id'] for r in source))))
    _line(directory,'Fig_Exp5_D_Pairings',pair,x_label='Actual tI',
          y_label='CSP pairing count',mode='line',show_p95=False,
          metadata=_metadata('Exp5',[e5],code_hash,
              SGX_NOTE+' Operation-count identity, not a latency or asymptotic proof.',
              'actual_tI','count'))
    ids.append('Fig_Exp5_D_Pairings')
    breakdown=[]
    for n,hit in ((5,'SMALL'),(20,'MEDIUM'),(40,'LARGE')):
        candidates=[r for r in e5['rows'] if r['variables']['policy_shape']=='threshold' and
                    r['variables']['N']==n and r['variables']['requested_L_hit']==hit]
        if len(candidates)!=20:raise ValueError('Exp5 representative slice absent')
        for name,metric in (('E2E','request_e2e_ns'),('TEEAuthorize','tee_authorize_ns'),
                            ('Transform','transform_ns'),('FinalDec','finaldec_ns')):
            breakdown.append(dict(stage=f'N{n} {name}',N=n,component=name,
                median_ms=statistics.median(r['metrics'][metric] for r in candidates)/1_000_000,
                configuration_id=candidates[0]['configuration_id'],
                dataset_manifest_sha256=e5['manifest_sha256']))
    bar_figure(directory,'Fig_Exp5_F_E2E_Components',breakdown,label='stage',
        value='median_ms',title='Exp5 representative timing observations',
        ylabel='Median duration (ms)',metadata=dict(_metadata('Exp5',[e5],code_hash,
            SGX_NOTE+' E2E and component bars are separate observations; they are not summed.',
            'N and stage','ms','threshold SMALL N5, MEDIUM N20, LARGE N40; n=20 each'),statistic='median; nonadditive'))
    ids.append('Fig_Exp5_F_E2E_Components')
    write_json(directory/'recommended_core_set.json',dict(
        selection_rule='One or two main figures per RQ; coverage and nonredundancy, not result favorability',
        recommended=['Fig_Exp1_A_Encrypt','Fig_Exp1_B_Transform',
                     'Fig_Exp3_A_Storage','Fig_Exp3_B_Breakdown',
                     'Fig_Exp4_A_Policy_Token','Fig_Exp4_F_AF_Query',
                     'Fig_Exp5_C_Transform','Fig_Exp5_E_E2E'],
        appendix_candidates=sorted(set(ids)-set(['Fig_Exp1_A_Encrypt','Fig_Exp1_B_Transform',
                     'Fig_Exp3_A_Storage','Fig_Exp3_B_Breakdown',
                     'Fig_Exp4_A_Policy_Token','Fig_Exp4_F_AF_Query',
                     'Fig_Exp5_C_Transform','Fig_Exp5_E_E2E']))))
    captions=['# Phase 5B figure captions','',
        'Each figure has a machine-readable source-data CSV and metadata JSON.','']
    for figure_id in ids:
        meta=json.loads((directory/f'figure_{figure_id}_metadata.json').read_text())
        captions.append(f'## {figure_id}\n\n{meta["caption"]} '
                        f'Unit: {meta["unit"]}; source: '
                        f'`figure_{figure_id}_data.csv`.\n')
    write_text(directory/'FIGURE_CAPTIONS.md','\n'.join(captions)+'\n')
    return ids
