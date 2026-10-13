"""No-overwrite Phase 5C calibration, frozen collection and analysis CLI."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .phase5c import (BUILD, ROOT, _write_new, make_plan, validate_dataset,
    validate_plan, validate_run)
from .phase5c_collect import calibrate, collect_exp6, collect_exp7
from .phase5c_report import compare, generate, verify
from .provenance import code_manifest


def main(argv=None):
    parser=argparse.ArgumentParser(prog='myabe08-phase5c')
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('calibrate');p.add_argument('--build',type=Path,default=BUILD)
    p.add_argument('--output',type=Path,default=ROOT/'calibration.json')
    p=sub.add_parser('plan');p.add_argument('calibration',type=Path)
    p.add_argument('--output',type=Path,default=ROOT/'PHASE5C_PLAN.json')
    p=sub.add_parser('freeze-code');p.add_argument('--output',type=Path,
        default=ROOT/'PHASE5C_CODE_MANIFEST.json')
    p=sub.add_parser('run');p.add_argument('experiment',choices=('Exp6','Exp7'))
    p.add_argument('--plan',type=Path,default=ROOT/'PHASE5C_PLAN.json')
    p.add_argument('--code',type=Path,default=ROOT/'PHASE5C_CODE_MANIFEST.json')
    p.add_argument('--build',type=Path,default=BUILD)
    p.add_argument('--root',type=Path,default=ROOT)
    p=sub.add_parser('validate-run');p.add_argument('path',type=Path)
    p=sub.add_parser('validate-dataset');p.add_argument('paths',nargs='+',type=Path)
    p=sub.add_parser('analyze');p.add_argument('exp6',type=Path)
    p.add_argument('exp7',type=Path)
    p=sub.add_parser('verify-analysis');p.add_argument('path',type=Path)
    p=sub.add_parser('compare-analysis');p.add_argument('first',type=Path)
    p.add_argument('second',type=Path)
    args=parser.parse_args(argv)
    try:
        if args.command=='calibrate':
            value=calibrate(build_dir=args.build)
            args.output.parent.mkdir(parents=True,exist_ok=True)
            _write_new(args.output,value)
            result=dict(status='COMPLETE',path=str(args.output),
                calibration=value)
        elif args.command=='plan':
            c=json.loads(args.calibration.read_text())
            if c['schema']!='MYABE08-PHASE5C-CALIBRATION-V1':
                raise ValueError('calibration schema mismatch')
            value=make_plan(keygen_calibration_ns=c['keygen_median_ns'],
                update_calibration_ns=c['update_median_ns'],
                active_calibration_ns=c['active_authorize_median_ns'])
            validate_plan(value)
            args.output.parent.mkdir(parents=True,exist_ok=True)
            _write_new(args.output,value)
            result=dict(status='COMPLETE',path=str(args.output),
                plan_sha256=value['plan_sha256'],plan_kind=value['plan_kind'],
                rl_grid=value['rl_grid'],n_reg_grid=value['n_reg_grid'])
        elif args.command=='freeze-code':
            value=code_manifest()
            args.output.parent.mkdir(parents=True,exist_ok=True)
            _write_new(args.output,value)
            result=dict(status='COMPLETE',path=str(args.output),
                        code_tree_sha256=value['tree_sha256'],files=len(value['files']))
        elif args.command=='run':
            plan=json.loads(args.plan.read_text())
            code=json.loads(args.code.read_text())
            path=(collect_exp6 if args.experiment=='Exp6' else collect_exp7)(
                plan,code,root=args.root,build_dir=args.build)
            result=dict(status='COMPLETE',run_path=str(path),
                        validation=validate_run(path))
        elif args.command=='validate-run':
            result=validate_run(args.path)
        elif args.command=='validate-dataset':
            result=validate_dataset(args.paths)
        elif args.command=='analyze':
            path=generate(args.exp6,args.exp7)
            result=dict(status='COMPLETE',analysis_path=str(path),
                        verification=verify(path))
        elif args.command=='verify-analysis':
            result=verify(args.path)
        else:
            result=compare(args.first,args.second)
        print(json.dumps(result,sort_keys=True,ensure_ascii=False))
        return 0
    except (ValueError,KeyError,OSError,TypeError,RuntimeError) as exc:
        print(json.dumps(dict(status='FAILED',error_class=type(exc).__name__,
                              detail=str(exc)),sort_keys=True,ensure_ascii=False))
        return 2


if __name__=='__main__':
    raise SystemExit(main())
