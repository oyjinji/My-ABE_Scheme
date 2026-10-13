"""Phase 5A controlled measurements, separate from Phase 4F smoke runs.

All cryptographic work goes through PublicMyABE08.  This module constructs
public structural inputs, schedules attempts, and validates immutable data.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import gc
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import tempfile
import time

from ..profile import EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1
from ..real_tee.client import SgxDebugClient
from ..types import Validity
from .provenance import (REPO, code_manifest, environment_manifest,
                         git_provenance, spec_manifest)
from .runner import (_case, _failure_row, _new_scheme, _row,
                     _trust_metadata)
from .schema import NOT_OBSERVED, build_plan, finalize_plan_hash
from .storage import RunArtifacts, canonical_storage_breakdown, validate_run
from .workloads import (generate_benchmark_workload, generate_workload, canonical_json,
                        sha256_json)

PHASE = 'PHASE_5A'
ORDER_SEED = 20260925
REAL = SGX_DEBUG_GRAMINE_V1
EMU = EMULATED_TEE_PROFILE
EXPERIMENTS = ('Exp1','Exp3','Exp4','Exp5')
DEFAULT_ROOT = REPO/'artifacts/myabe08/benchmarks/phase5a'


def _config(experiment, backend, *, shape, ell, cmax, N, hit_codes,
            threshold=2, regime=None, L_hit=None, seed=17):
    value=dict(experiment_id=experiment,backend=backend,shape=shape,
        ell=ell,cmax=cmax,N=N,hit_codes=hit_codes,threshold=threshold,
        repeat_regime=regime,L_hit=L_hit,workload_seed=seed)
    value['configuration_id']='CFG-'+sha256_json(value)[:20]
    return value


def build_phase5a_plan(*, repetitions=30, warmups=5):
    """Balanced design selected after calibrating the full factorial budget.

    Fixed row patterns need one structural seed; crypto randomness is never
    seeded.  Exp3 is deterministic canonical byte accounting, one artifact.
    """
    if type(repetitions) is not int or repetitions < 20 or type(warmups) is not int or warmups < 0:
        raise ValueError('Phase 5A latency sampling below minimum')
    configs=[]
    for ell in (5,10,20,40):
        for regime,cmax in (('UNIQUE',1),('LOW_REPEAT',2),
                            ('MEDIUM_REPEAT',3),('HIGH_REPEAT',4)):
            u=(ell+cmax-1)//cmax
            configs.append(_config('Exp1',REAL,shape='threshold',ell=ell,
                cmax=cmax,N=min(u,2),hit_codes=min(u,2),regime=regime))
    for ell in (5,10,20,40,80,160):
        for cmax in (1,2,3,4,5):
            u=(ell+cmax-1)//cmax
            configs.append(_config('Exp3',EMU,shape='threshold',ell=ell,
                cmax=cmax,N=max(2,min(ell,20)),hit_codes=min(u,2),
                regime='STORAGE'))
    for backend in (EMU,REAL):
        # Orthogonal balanced coverage, not a Cartesian factorial.  The
        # policy/user token interfaces operate on a whole list per call.
        for ell,N,cmax,label in ((2,1,1,'LOW'),(5,5,1,'HIGH'),
            (10,10,2,'MEDIUM'),(20,20,3,'HIGH'),(40,40,4,'LOW'),
            (80,80,1,'HIGH')):
            u=(ell+cmax-1)//cmax
            hit={'LOW':1,'MEDIUM':max(1,u//2),'HIGH':u}[label]
            configs.append(_config('Exp4',backend,shape='OR',ell=ell,
                cmax=cmax,N=N,hit_codes=hit,L_hit=label))
        for label,hit in (('LOW',1),('MEDIUM',5),('HIGH',10)):
            configs.append(_config('Exp4',backend,shape='OR',ell=20,
                cmax=2,N=20,hit_codes=hit,L_hit=label))
    for N in (5,10,20,40):
        ell=N
        for label,fraction in (('SMALL',.25),('MEDIUM',.5),('LARGE',1.0)):
            hit=max(2,round(ell*fraction))
            configs.append(_config('Exp5',REAL,shape='threshold',ell=ell,
                cmax=1,N=N,hit_codes=hit,L_hit=label))
    configs.extend((
        _config('Exp5',REAL,shape='AND',ell=2,cmax=1,N=5,hit_codes=2,
                L_hit='AND'),
        _config('Exp5',REAL,shape='threshold',ell=5,cmax=1,N=5,
                hit_codes=5,threshold=3,L_hit='THRESHOLD_3'),
        _config('Exp5',REAL,shape='threshold',ell=10,cmax=1,N=10,
                hit_codes=10,threshold=5,L_hit='THRESHOLD_5'),
        _config('Exp5',REAL,shape='repeated',ell=5,cmax=3,N=5,
                hit_codes=2,L_hit='REPEATED'),
    ))
    configs=list({c['configuration_id']:c for c in configs}.values())
    # A full-factorial plan exceeds six hours even under the optimistic
    # calibration; retain every named variable in the balanced design.
    plan=dict(phase=PHASE, benchmark_eligible=True,
        plan_kind='REDUCED_BALANCED_PLAN',
        reduction_reason='full Cartesian grid exceeds six-hour execution budget',
        original_grid=dict(Exp1={'ell':[5,10,20,40,80],
            'repeat_regime':['UNIQUE','LOW_REPEAT','MEDIUM_REPEAT','HIGH_REPEAT']},
            Exp3={'ell':[5,10,20,40,80,160],'cmax':[1,2,3,4,5]},
            Exp4={'N':[5,10,20,40,80],'ell':[5,10,20,40,80],
                'cmax':[1,2,3,4],'L_hit':['LOW','MEDIUM','HIGH'],
                'policy_batch_size':[1,5,10,20,40],
                'user_batch_size':[1,5,10,20,40]},
            Exp5={'N':[5,10,20,40,80],
                'candidate_ratio':[.25,.5,1.0],
                'shape':['AND','threshold','repeated']}),
        execution_order_seed=ORDER_SEED, warmups=warmups,
        repetitions=repetitions, storage_repetitions=1,
        repetition_reduced_for_runtime=(repetitions<30),
        blocks=3, per_sample_timeout_ns=120_000_000_000,
        workload_seed_policy='FIXED_STRUCTURE_ONE_SEED; CSPRNG_UNSEEDED',
        configurations=configs,
        expected_samples={exp:sum((1 if exp=='Exp3' else repetitions)
            for c in configs if c['experiment_id']==exp) for exp in EXPERIMENTS},
        phase5a_plan_sha256=None)
    plan['phase5a_plan_sha256']=sha256_json({k:v for k,v in plan.items()
                                              if k!='phase5a_plan_sha256'})
    return plan


def validate_phase5a_plan(plan):
    if (plan.get('phase')!=PHASE or plan.get('benchmark_eligible') is not True or
        plan.get('phase5a_plan_sha256')!=sha256_json({k:v for k,v in plan.items()
            if k!='phase5a_plan_sha256'}) or
        len({c['configuration_id'] for c in plan['configurations']})!=
            len(plan['configurations'])):
        raise ValueError('Phase 5A plan invalid')
    for c in plan['configurations']:
        identity={k:v for k,v in c.items() if k!='configuration_id'}
        if c['configuration_id']!='CFG-'+sha256_json(identity)[:20]:
            raise ValueError('Phase 5A configuration hash mismatch')
        _spec(c)
    return True


def _spec(config):
    return generate_benchmark_workload(shape=config['shape'],ell=config['ell'],
        cmax=config['cmax'],N=config['N'],hit_codes=config['hit_codes'],
        threshold=config['threshold'],seed=config['workload_seed'],
        requested={'J':config['hit_codes']*config['cmax'],
            'L_hit':config['L_hit'] or 'NOT_APPLICABLE',
            'repeat_regime':config['repeat_regime'] or 'NOT_APPLICABLE'})


def _run_plan(plan, experiment, backend, cmax=None):
    configs=[c for c in plan['configurations'] if c['experiment_id']==experiment
             and c['backend']==backend and (cmax is None or c['cmax']==cmax)]
    if not configs:
        raise ValueError('empty Phase 5A cohort')
    if len({c['cmax'] for c in configs})!=1:
        raise ValueError('select one cmax per run; Setup cannot change cmax')
    reps=1 if experiment=='Exp3' else plan['repetitions']
    sampling=finalize_plan_hash(build_plan((experiment,),backend,
        seeds=(17,),warmups=0 if experiment=='Exp3' else plan['warmups'],
        repetitions=reps,max_samples=len(configs)*reps,
        allow_large_run=True))
    sampling.update(phase=PHASE,benchmark_eligible=True,
        phase5a_plan_sha256=plan['phase5a_plan_sha256'],
        configurations=configs,estimated_measured_samples=len(configs)*reps,
        execution_order_seed=plan['execution_order_seed'],
        blocks=plan['blocks'],per_sample_timeout_ns=plan['per_sample_timeout_ns'])
    sampling['entries'][0]['status']='BENCHMARK'
    sampling['entries'][0]['families']=sorted({'B-'+c['shape'] for c in configs})
    sampling['workload_families']=sampling['entries'][0]['families']
    sampling['variable_grid']={'configuration_id':[c['configuration_id'] for c in configs]}
    return finalize_plan_hash(sampling)


def _system_snapshot():
    try: load=list(os.getloadavg())
    except OSError: load=None
    memory=None
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                memory=int(line.split()[1])*1024;break
    except OSError: pass
    try: frequency=Path('/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq').read_text().strip()
    except OSError: frequency='UNAVAILABLE'
    return dict(load_average=load,memory_available_bytes=memory,
        cpu_frequency_khz=frequency,gc_enabled=gc.isenabled(),
        utc=datetime.now(timezone.utc).isoformat())


@contextmanager
def _pin_cpu():
    if not hasattr(os,'sched_getaffinity'):
        yield 'UNCONTROLLED';return
    original=os.sched_getaffinity(0)
    if not original:
        yield 'UNCONTROLLED';return
    chosen=min(original)
    try:
        os.sched_setaffinity(0,{chosen})
    except OSError:
        yield 'UNCONTROLLED';return
    try: yield sorted(os.sched_getaffinity(0))
    finally: os.sched_setaffinity(0,original)


@contextmanager
def _real_service(build_dir):
    client=SgxDebugClient()
    with tempfile.TemporaryDirectory(prefix='myabe08-phase5a-service-') as tmp:
        log=Path(tmp)/'service.log'
        with log.open('wb') as output:
            process=subprocess.Popen(('bash',str(REPO/
                'src/core/myabe08/real_tee/gramine/run_sgx.sh')),
                cwd=REPO,env=dict(os.environ,MYABE08_SGX_DEBUG_BUILD_DIR=str(build_dir)),
                stdout=output,stderr=subprocess.STDOUT)
            try:
                for _ in range(300):
                    if process.poll() is not None:
                        raise RuntimeError('Gramine SGX service exited during startup')
                    try:
                        client.health();break
                    except (ConnectionError,OSError,TimeoutError):
                        time.sleep(.1)
                else: raise TimeoutError('Gramine SGX service startup timeout')
                yield client
            finally:
                if process.poll() is None:
                    try: client.stop_test_service();process.wait(timeout=10)
                    except Exception:
                        process.terminate();process.wait(timeout=10)
                content=log.read_text(errors='replace')
                if 'SYNTHETIC-UID-' in content or 'SYN-' in content:
                    raise ValueError('TEST canary leaked into SGX service log')
                # No service log is copied into artifacts.


def _benchmark_row(scheme,spec,experiment,result,artifacts,trust,code_hash,
                   config,block_id,index,snapshot):
    row=_row(scheme,spec,experiment,result,artifacts,trust,code_hash)
    row.update(configuration_id=config['configuration_id'],block_id=block_id,
        sample_index_within_block=index,block_environment=snapshot,
        request_class='ACTIVE_AUTHORIZED')
    variables=row['variables']
    variables.update(actual_cmax=result['ct'].header.c_max,
        d_j_count=len(result['ct'].occurrence_components),
        requested_cmax=config['cmax'],requested_L_hit=config['L_hit'],
        actual_L_hit=len({spec.row_codes[i-1] for i in
            result['partial'].candidate_rows}),
        policy_batch_size=spec.ell,user_batch_size=spec.N,
        repetition_reduced_for_runtime=artifacts.plan['repetitions']<30,
        requested_k=config['threshold'],actual_k=len(result['partial'].reconstruction_rows),
        repeat_regime=config['repeat_regime'],
        requested_J=config['hit_codes']*config['cmax'])
    row['metrics']['attestation_preflight_ns']=NOT_OBSERVED
    row['metrics']['encrypt_core_ns']=result['encrypt_breakdown']['encrypt_core_ns']
    if experiment!='Exp3':
        row['metrics'].update(canonical_storage_breakdown(result['ct'],
            result['auth'],result['partial'],result['user'],scheme.crypto))
    return row


def execute_cohort(plan,experiment,backend,*,root=DEFAULT_ROOT,
                   build_dir=Path('/tmp/myabe08-sgx-ra-probe'),client=None,
                   cmax=None):
    validate_phase5a_plan(plan)
    if experiment not in EXPERIMENTS or backend not in (EMU,REAL):
        raise ValueError('unsupported Phase 5A cohort')
    run_plan=_run_plan(plan,experiment,backend,cmax)
    service=(_real_service(build_dir) if backend==REAL and client is None
             else nullcontext(client))
    with _pin_cpu() as affinity, service as active_client, tempfile.TemporaryDirectory(
            prefix='myabe08-phase5a-state-') as temporary:
        scheme=_new_scheme(backend,Path(temporary)/'kgc',build_dir,active_client)
        setup_started=time.perf_counter_ns()
        scheme.Setup(c_max=run_plan['configurations'][0]['cmax'],
                     validity=Validity(100,2000))
        setup_ns=time.perf_counter_ns()-setup_started
        environment=environment_manifest()
        environment['benchmark_cpu_affinity']=affinity
        trust=_trust_metadata(scheme,environment)
        cohort='REAL_SGX_DEBUG_FEASIBILITY' if backend==REAL else 'EMULATED_TEST'
        artifacts=RunArtifacts(run_plan,environment,code_manifest(),spec_manifest(),
            git_provenance(),root=Path(root)/experiment,
            trust_cohort=cohort,trust_metadata=trust,
            setup_with_preflight_ns=setup_ns,phase=PHASE,benchmark_eligible=True)
        artifacts.manifest['phase5a_plan_sha256']=plan['phase5a_plan_sha256']
        artifacts.manifest['attestation_preflight_ns']=scheme.attestation_preflight_ns
        artifacts.manifest['environment_start']=_system_snapshot()
        artifacts.manifest['cpu_affinity']=affinity
        artifacts.manifest['setup_cmax']=run_plan['configurations'][0]['cmax']
        configs=list(run_plan['configurations'])
        random.Random(plan['execution_order_seed']).shuffle(configs)
        artifacts.manifest['execution_order']=[c['configuration_id'] for c in configs]
        try:
            gate_spec=generate_workload('W-SINGLE',17)
            revocation_before=_case(scheme,gate_spec,'Exp6')
            privacy_before=_case(scheme,gate_spec,'Exp7')
            artifacts.manifest['preflight_gates']=dict(
                revoked_before_t0=revocation_before['correct'],
                transcript_privacy=privacy_before['correct'])
            if not all(artifacts.manifest['preflight_gates'].values()):
                artifacts.finalize('FAILED')
                return dict(status='CORRECTNESS_PRECHECK_FAILED',
                            run_path=str(artifacts.path))
            for config in configs:
                spec=_spec(config)
                try: precheck=_case(scheme,spec,experiment)
                except Exception as exc:
                    artifacts.record_precheck(dict(experiment_id=experiment,
                        workload_id=spec.workload_id,passed=False,
                        error_class=type(exc).__name__))
                    artifacts.finalize('FAILED')
                    return dict(status='CORRECTNESS_PRECHECK_FAILED',
                                run_path=str(artifacts.path))
                passed=precheck['correct']
                artifacts.record_precheck(dict(experiment_id=experiment,
                    workload_id=spec.workload_id,
                    workload_spec_sha256=spec.workload_spec_sha256,
                    configuration_id=config['configuration_id'],
                    expected_outcome=precheck['expected_outcome'],
                    actual_outcome=precheck['actual_outcome'],passed=passed))
                if not passed:
                    artifacts.finalize('FAILED')
                    return dict(status='CORRECTNESS_PRECHECK_FAILED',
                                run_path=str(artifacts.path))
                for _ in range(run_plan['warmups']):
                    warm=_case(scheme,spec,experiment)
                    if not warm['correct']:
                        artifacts.finalize('FAILED')
                        return dict(status='CORRECTNESS_PRECHECK_FAILED',
                                    run_path=str(artifacts.path))
                reps=run_plan['repetitions']
                block_size=(reps+run_plan['blocks']-1)//run_plan['blocks']
                for sample_number in range(reps):
                    block_id=sample_number//block_size
                    within=sample_number%block_size
                    if within==0: snapshot=_system_snapshot()
                    started=time.perf_counter_ns()
                    try:
                        result=_case(scheme,spec,experiment)
                        elapsed=time.perf_counter_ns()-started
                        row=_benchmark_row(scheme,spec,experiment,result,artifacts,
                            trust,artifacts.manifest['code_manifest_sha256'],
                            config,block_id,within,snapshot)
                        if elapsed>run_plan['per_sample_timeout_ns']:
                            row.update(sample_status='TIMEOUT',actual_outcome='TIMEOUT',
                                correctness_verified=False,error_class='SampleTimeout')
                    except Exception as exc:
                        row=_failure_row(scheme,spec,experiment,artifacts,trust,
                            artifacts.manifest['code_manifest_sha256'],exc,
                            time.perf_counter_ns()-started)
                        row.update(configuration_id=config['configuration_id'],
                            block_id=block_id,sample_index_within_block=within,
                            block_environment=snapshot,request_class='ACTIVE_AUTHORIZED')
                    artifacts.append_row(row)
                    if row['sample_status'] not in ('OK','EXPECTED_REJECT'):
                        artifacts.finalize('FAILED')
                        return dict(status='MEASURED_SAMPLE_FAILED',
                                    run_path=str(artifacts.path))
            revocation_after=_case(scheme,gate_spec,'Exp6')
            artifacts.manifest['preflight_gates']['revoked_after_run']=revocation_after['correct']
            if not revocation_after['correct']:
                artifacts.finalize('FAILED')
                return dict(status='CORRECTNESS_REGRESSION',
                            run_path=str(artifacts.path))
            artifacts.manifest['environment_end']=_system_snapshot()
            path=artifacts.finalize('COMPLETE')
            return dict(status='COMPLETE',run_path=str(path),
                        validation=validate_run(path),measured_rows=artifacts.raw_count)
        except BaseException:
            if artifacts.manifest['status']=='RUNNING': artifacts.finalize('INTERRUPTED')
            raise


def summarize_run(path):
    check=validate_run(path)
    rows=[json.loads(x) for x in (Path(path)/'raw.jsonl').read_text().splitlines()]
    groups={}
    for row in rows: groups.setdefault(row['configuration_id'],[]).append(row)
    summary=[]
    for config_id,samples in sorted(groups.items()):
        successful=[x for x in samples if x['sample_status']=='OK']
        metric='ct_total_bytes' if samples[0]['experiment_id']=='Exp3' else 'request_e2e_ns'
        values=[x['metrics'][metric] for x in successful
                if type(x['metrics'].get(metric)) is int]
        summary.append(dict(run_id=check['run_id'],configuration_id=config_id,
            sample_ids=[x['sample_id'] for x in samples],n=len(values),
            failed_count=len(samples)-len(successful),metric=metric,
            unit='bytes' if metric.endswith('bytes') else 'ns',
            descriptive=({name:func(values) for name,func in (
                ('min',min),('median',statistics.median),('mean',statistics.mean),
                ('std',statistics.pstdev),('p95',lambda x:sorted(x)[
                    min(len(x)-1,int(.95*(len(x)-1)))]),('max',max))} if values else None)))
    return summary


def validate_dataset(paths):
    paths=[Path(x) for x in paths]
    if not paths: raise ValueError('empty dataset')
    manifests=[]
    for path in paths:
        validate_run(path)
        manifests.append(json.loads((path/'manifest.json').read_text()))
    reference=manifests[0]
    config_ids=[]
    for path in paths:
        run_plan=json.loads((path/'plan.json').read_text())
        config_ids.extend(c['configuration_id'] for c in run_plan['configurations'])
    if len(config_ids)!=len(set(config_ids)):
        raise ValueError('duplicate configurations across dataset runs')
    for manifest in manifests[1:]:
        if (manifest['spec']['sha256']!=reference['spec']['sha256'] or
            manifest['code_manifest_sha256']!=reference['code_manifest_sha256'] or
            manifest['metric_units_sha256']!=reference['metric_units_sha256'] or
            manifest['phase5a_plan_sha256']!=reference['phase5a_plan_sha256'] or
            manifest['trust_cohort']!=reference['trust_cohort'] or
            manifest['backend']!=reference['backend'] or
            manifest['environment_fingerprint']!=reference['environment_fingerprint']):
            raise ValueError('incompatible dataset provenance or trust cohort')
    frozen_path=REPO/'src/core/myabe08/experiments/phase5a_plan.json'
    if frozen_path.is_file():
        frozen=json.loads(frozen_path.read_text())
        if frozen.get('phase5a_plan_sha256')==reference['phase5a_plan_sha256']:
            selected={c['configuration_id'] for c in frozen['configurations']
                if c['experiment_id']==reference['experiment_ids'][0] and
                   c['backend']==reference['backend']}
            if set(config_ids)!=selected:
                raise ValueError('frozen Phase 5A configuration coverage incomplete')
    return dict(status='PASS',run_ids=[x['run_id'] for x in manifests],
        sample_count=sum(x['measured_row_count'] for x in manifests),
        code_manifest_sha256=reference['code_manifest_sha256'],
        trust_cohort=reference['trust_cohort'])


def freeze_dataset(paths):
    """Write a new cohort manifest and descriptive summary, never overwrite."""
    paths=[Path(x) for x in paths]
    checked=validate_dataset(paths)
    parents={p.parent for p in paths}
    if len(parents)!=1:
        raise ValueError('dataset runs must share one cohort directory')
    parent=parents.pop()
    manifests=[json.loads((p/'manifest.json').read_text()) for p in paths]
    experiments={tuple(x['experiment_ids']) for x in manifests}
    if len(experiments)!=1:
        raise ValueError('dataset cannot mix experiments')
    summaries=[entry for p in paths for entry in summarize_run(p)]
    failed=sum(row['failed_count'] for row in summaries)
    summary_path=parent/'descriptive_summary.json'
    manifest_path=parent/'dataset_manifest.json'
    if summary_path.exists() or manifest_path.exists():
        raise FileExistsError('dataset is immutable')
    with summary_path.open('xb') as output:
        output.write(canonical_json(dict(phase=PHASE,
            note='descriptive statistics only; no paper conclusion',
            rows=summaries))+b'\n')
    manifest=dict(phase=PHASE,benchmark_eligible=True,
        dataset_id='MYABE08-PHASE5A-'+experiments.pop()[0].upper(),
        run_ids=checked['run_ids'],configuration_count=len(summaries),
        sample_count=checked['sample_count'],failed_sample_count=failed,
        code_manifest_sha256=checked['code_manifest_sha256'],
        environment_fingerprint=manifests[0]['environment_fingerprint'],
        trust_cohort=checked['trust_cohort'],
        backend=manifests[0]['backend'],
        spec_sha256=manifests[0]['spec']['sha256'],
        phase5a_plan_sha256=manifests[0]['phase5a_plan_sha256'],
        metric_units_sha256=manifests[0]['metric_units_sha256'],
        descriptive_summary_sha256=__import__('hashlib').sha256(
            summary_path.read_bytes()).hexdigest(),validation='PASS')
    with manifest_path.open('xb') as output:
        output.write(canonical_json(manifest)+b'\n')
    return dict(dataset_manifest=str(manifest_path),
        descriptive_summary=str(summary_path),**checked)
