"""Stable JSON CLI for planning, TEST smoke and artifact validation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ..profile import EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1
from .registry import REGISTRY, get_experiment
from .runner import run_smoke
from .schema import build_plan, finalize_plan_hash
from .storage import validate_run
from .workloads import canonical_json
from .phase5a import (build_phase5a_plan, validate_phase5a_plan,
    execute_cohort, validate_dataset, summarize_run, freeze_dataset, DEFAULT_ROOT)


def _output(value):
    print(json.dumps(value, sort_keys=True, ensure_ascii=False))


def _selection(value):
    return tuple(REGISTRY) if value == 'all' else (value,)


def _sampling(parser):
    parser.add_argument('experiment', choices=tuple(REGISTRY) + ('all',))
    parser.add_argument('--backend', choices=(EMULATED_TEE_PROFILE,
                        SGX_DEBUG_GRAMINE_V1), required=True)
    parser.add_argument('--seed', type=int, action='append')
    parser.add_argument('--warmups', type=int, default=0)
    parser.add_argument('--repetitions', type=int, default=1)
    parser.add_argument('--max-samples', type=int, default=32)
    parser.add_argument('--allow-large-run', action='store_true')


def _parser():
    parser = argparse.ArgumentParser(prog='myabe08-experiments')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list')
    description = sub.add_parser('describe')
    description.add_argument('experiment', choices=tuple(REGISTRY))
    plan = sub.add_parser('plan'); _sampling(plan)
    plan.add_argument('--output', type=Path)
    smoke = sub.add_parser('smoke'); _sampling(smoke)
    smoke.add_argument('--root', type=Path)
    smoke.add_argument('--build-dir', type=Path)
    smoke.add_argument('--run-id')
    validation = sub.add_parser('validate-run')
    validation.add_argument('path', type=Path)
    validation.add_argument('--canary', action='append', default=[])
    inspection = sub.add_parser('inspect-run')
    inspection.add_argument('path', type=Path)
    phase_plan=sub.add_parser('phase5a-plan')
    phase_plan.add_argument('--output',type=Path,required=True)
    phase_plan.add_argument('--repetitions',type=int,default=30)
    phase_plan.add_argument('--warmups',type=int,default=5)
    phase_run=sub.add_parser('phase5a-run')
    phase_run.add_argument('experiment',choices=('Exp1','Exp3','Exp4','Exp5'))
    phase_run.add_argument('--backend',choices=(EMULATED_TEE_PROFILE,
        SGX_DEBUG_GRAMINE_V1),required=True)
    phase_run.add_argument('--plan',type=Path,required=True)
    phase_run.add_argument('--cmax',type=int)
    phase_run.add_argument('--root',type=Path,default=DEFAULT_ROOT)
    phase_run.add_argument('--build-dir',type=Path,
                           default=Path('/tmp/myabe08-sgx-ra-probe'))
    dataset=sub.add_parser('validate-dataset')
    dataset.add_argument('paths',type=Path,nargs='+')
    freezing=sub.add_parser('freeze-dataset')
    freezing.add_argument('paths',type=Path,nargs='+')
    summary=sub.add_parser('summarize-run')
    summary.add_argument('path',type=Path)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        if args.command == 'list':
            _output([dict(experiment_id=x.experiment_id,
                contribution=x.contribution, status=x.status,
                supported_backends=x.supported_backends,
                blocked_reason=x.blocked_reason) for x in REGISTRY.values()])
            return 0
        if args.command == 'describe':
            _output(get_experiment(args.experiment).public())
            return 0
        if args.command in ('plan','smoke'):
            selection = _selection(args.experiment)
            seeds = tuple(args.seed or (17,))
            if args.command == 'plan':
                plan = finalize_plan_hash(build_plan(selection,args.backend,
                    seeds=seeds,warmups=args.warmups,repetitions=args.repetitions,
                    max_samples=args.max_samples,
                    allow_large_run=args.allow_large_run))
                if args.output:
                    with args.output.open('xb') as stream:
                        stream.write(canonical_json(plan)+b'\n')
                _output(plan)
                return 0
            result = run_smoke(selection,args.backend,root=args.root,
                seeds=seeds,warmups=args.warmups,repetitions=args.repetitions,
                max_samples=args.max_samples,allow_large_run=args.allow_large_run,
                build_dir=args.build_dir,run_id=args.run_id)
            _output(result)
            return 0 if result['status'] in ('COMPLETE','BLOCKED_COMMON_BACKEND') else 2
        if args.command == 'validate-run':
            _output(validate_run(args.path,canaries=args.canary))
            return 0
        if args.command == 'inspect-run':
            manifest = json.loads((args.path/'manifest.json').read_text())
            _output({key:manifest.get(key) for key in ('schema_version','run_id',
                'backend','experiment_ids','trust_cohort','status','started_utc',
                'ended_utc','duration_ns','measured_row_count')})
            return 0
        if args.command == 'phase5a-plan':
            value=build_phase5a_plan(repetitions=args.repetitions,
                warmups=args.warmups)
            validate_phase5a_plan(value)
            with args.output.open('xb') as stream:
                stream.write(canonical_json(value)+b'\n')
            _output(dict(status='COMPLETE',plan_path=str(args.output),
                phase5a_plan_sha256=value['phase5a_plan_sha256'],
                expected_samples=value['expected_samples']))
            return 0
        if args.command == 'phase5a-run':
            value=json.loads(args.plan.read_text())
            result=execute_cohort(value,args.experiment,args.backend,
                root=args.root,build_dir=args.build_dir,cmax=args.cmax)
            _output(result)
            return 0 if result['status']=='COMPLETE' else 2
        if args.command == 'validate-dataset':
            _output(validate_dataset(args.paths))
            return 0
        if args.command == 'freeze-dataset':
            _output(freeze_dataset(args.paths))
            return 0
        if args.command == 'summarize-run':
            _output(summarize_run(args.path))
            return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # Only a code, never repr of a secret-bearing object or exception text.
        _output(dict(status='REJECTED',error_class=type(exc).__name__))
        return 2
    except Exception as exc:
        _output(dict(status='FAILED',error_class=type(exc).__name__))
        return 2
    return 2
