"""Reproducible CLI for frozen Phase 5A data analysis."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import COHORTS, analysis_code_hash, load_frozen, statistics_rows
from .report import compare_bundles, generate_all, verify_bundle


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(prog='myabe08-analysis')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('validate')
    for command in ('summarize','plot','table'):
        part=sub.add_parser(command)
        part.add_argument('experiment',choices=('Exp1','Exp3','Exp4','Exp5'))
    sub.add_parser('all')
    verify=sub.add_parser('verify');verify.add_argument('bundle',type=Path)
    compare=sub.add_parser('compare');compare.add_argument('first',type=Path)
    compare.add_argument('second',type=Path)
    args=parser.parse_args(argv)
    try:
        if args.command=='validate':
            loaded=load_frozen()
            value=dict(status='PASS',cohorts=[dict(experiment=e,backend=b,
                runs=len(loaded['cohorts'][(e,b)]['run_ids']),
                samples=len(loaded['cohorts'][(e,b)]['rows'])) for e,b in COHORTS],
                excluded_superseded_runs_count=loaded['excluded_superseded_runs_count'],
                excluded_superseded_run_ids=loaded['excluded_superseded_run_ids'])
        elif args.command=='summarize':
            loaded=load_frozen();code_hash=analysis_code_hash()
            records=[]
            for e,b in COHORTS:
                if e==args.experiment:
                    records.extend(statistics_rows(loaded['cohorts'][(e,b)],e,b))
            value=dict(status='PASS',experiment=args.experiment,
                analysis_code_sha256=code_hash,statistics_rows=len(records),
                configurations=len({r['configuration_id'] for r in records}))
        elif args.command in ('all','plot','table'):
            bundle=generate_all()
            value=dict(status='COMPLETE',requested_action=args.command,
                       requested_experiment=getattr(args,'experiment',None),
                       analysis_path=str(bundle),verification=verify_bundle(bundle))
        elif args.command=='verify':
            value=verify_bundle(args.bundle)
        else:
            value=compare_bundles(args.first,args.second)
        print(json.dumps(value,sort_keys=True,ensure_ascii=False))
        return 0
    except (ValueError,KeyError,OSError,TypeError) as exc:
        print(json.dumps(dict(status='FAILED',error_class=type(exc).__name__,
                              detail=str(exc)),sort_keys=True,ensure_ascii=False))
        return 2
