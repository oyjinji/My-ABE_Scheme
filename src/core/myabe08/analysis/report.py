"""Generate and verify immutable Phase 5B analysis bundles."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re

from . import ANALYSIS_SCHEMA
from .core import (COHORTS, ENVIRONMENT_HASH, OUTPUT_ROOT, REPO, SPEC_HASH, analysis_code_hash,
    load_frozen, new_analysis_dir, sha256_file, write_json, write_text)
from .products import (EMU, SGX, SGX_NOTE, produce_figures,
                       produce_summaries, produce_tables)


FORBIDDEN_CLAIMS = ('production-ready','fully anonymous','proven secure',
    'outperforms FABEO','state-of-the-art','zero-cost revocation',
    'remote attestation PASS','RA2 PASS','faster than FABEO',
    'proves unlinkability','proves independence','asymptotically efficient proof')


def claim_lint(paper: Path) -> dict:
    hits=[]
    for file in sorted(paper.glob('*.md')):
        for number,line in enumerate(file.read_text().splitlines(),1):
            for phrase in FORBIDDEN_CLAIMS:
                if phrase.casefold() in line.casefold():
                    hits.append(dict(file=file.name,line=number,phrase=phrase))
    return dict(status='PASS' if not hits else 'FAIL',scanned_files=len(list(paper.glob('*.md'))),
                hits=hits)


def _one(rows, **where):
    found=[row for row in rows if all(row.get(k)==v for k,v in where.items())]
    if len(found)!=1:
        raise ValueError('paper anchor configuration not unique')
    return found[0]


def _paper_intro(experiment: str, cohort: str) -> str:
    sampling = ('Exp3 reports one canonical storage artifact per configuration; '
        'latency inference is not applicable.\n\n' if experiment == 'Exp3' else
        'Each latency configuration has 20 measured samples. Medians are '
        'descriptive; no inferential confidence interval or hypothesis test '
        'is reported because each configuration has one run and only three '
        'contiguous blocks.\n\n')
    return (f'# {experiment} Results draft\n\n'
        f'Analysis schema: {ANALYSIS_SCHEMA}. Source: frozen Phase 5A {cohort}. '
        'All reported numbers are generated from the linked machine tables and '
        'configuration IDs; raw JSONL remains authoritative. ' + sampling)


def produce_paper(bundle: Path, loaded: dict, tables: dict,
                  summaries: dict, figure_ids: list[str]) -> list[str]:
    paper=bundle/'paper'; files=[]
    exp1=tables['exp1_results']
    low=_one(exp1,ell=5,repeat_regime='UNIQUE')
    high=_one(exp1,ell=40,repeat_regime='UNIQUE')
    text=_paper_intro('Exp1','REAL_SGX_DEBUG_FEASIBILITY')+(
        '## Research question\n\nHow do policy size and occurrence structure '
        'relate to observed eight-algorithm costs and operation counts?\n\n'
        '## Experimental variables\n\nPolicy rows `ell={5,10,20,40}` and '
        'UNIQUE/LOW/MEDIUM/HIGH repeat regimes; actual `cmax`, `k`, and `tI` '
        'are retained per configuration.\n\n'
        '## Observed result\n\nWithin the UNIQUE regime, the measured '
        f'Encrypt median is {low["Encrypt_median_ms"]:.3f} ms at ell=5 and '
        f'{high["Encrypt_median_ms"]:.3f} ms at ell=40. Transform medians '
        f'for those configurations are {low["Transform_median_ms"]:.3f} and '
        f'{high["Transform_median_ms"]:.3f} ms.\n\n'
        '## Quantitative evidence\n\nThe cited configurations are '
        f'`{low["configuration_id"]}` and `{high["configuration_id"]}`. '
        f'Their Encrypt p95 values are {low["Encrypt_p95_ms"]:.3f} and '
        f'{high["Encrypt_p95_ms"]:.3f} ms. Across all Exp1 samples, '
        'TEE pairings equal 1, CSP pairings equal 1+tI, system pairings '
        'equal 2+tI, and FinalDec pairings equal 0. '
        'The per-row D count in the table is an analytical structural '
        'reference, not a measured implementation baseline.\n\n'
        '## Interpretation\n\nThese within-system observations are '
        'consistent with the recorded occurrence-slot and pairing structure. '
        'The selected policy regimes also change structural variables, so '
        'the figures are descriptive associations.\n\n'
        '## Boundary / caveat\n\n'+SGX_NOTE+' No naive per-row implementation '
        'was benchmarked. The data do not establish a security proof, '
        'causal scaling law, or cross-scheme speedup.\n\n'
        'Sources: [Exp1 table](../tables/TABLE_EXP1_RESULTS.md), '
        '[machine summary](../summary/EXP1_STATISTICS.csv), '
        '[figure data](../figures/figure_Fig_Exp1_A_Encrypt_data.csv).\n')
    write_text(paper/'RESULTS_EXP1.md',text);files.append('RESULTS_EXP1.md')

    exp3=tables['exp3_storage']
    small=_one(exp3,ell=5,cmax=1)
    large=_one(exp3,ell=160,cmax=1)
    text=_paper_intro('Exp3','EMULATED_TEST')+(
        '## Research question\n\nHow do canonical serialized objects vary '
        'with policy size and cmax?\n\n'
        '## Experimental variables\n\n`ell={5,10,20,40,80,160}` and '
        '`cmax={1,2,3,4,5}`; one canonical storage artifact per configuration.\n\n'
        '## Observed result\n\nFor cmax=1, CT total is '
        f'{small["CT_total_bytes"]} bytes at ell=5 and '
        f'{large["CT_total_bytes"]} bytes at ell=160.\n\n'
        '## Quantitative evidence\n\nThe cited configurations are '
        f'`{small["configuration_id"]}` and `{large["configuration_id"]}`. '
        'Every CT total reconciles to mutually exclusive CT-core, AF, '
        'header, DEM, and publication byte categories. Revocation CT '
        'components, public KU, and tree TK are not present in the current '
        'construction.\n\n'
        '## Interpretation\n\nThese are absolute canonical byte counts for '
        'the current implementation. The AF slot count is derived from '
        'recorded AF slot bytes and the frozen slot-width formula.\n\n'
        '## Boundary / caveat\n\nNo alternative ABE scheme or implementation '
        'was measured on the same backend. Storage absence does not imply '
        'absence of revocation processing costs.\n\n'
        'Sources: [Exp3 table](../tables/TABLE_EXP3_STORAGE.md), '
        '[machine summary](../summary/EXP3_STORAGE.csv), '
        '[figure data](../figures/figure_Fig_Exp3_A_Storage_data.csv).\n')
    write_text(paper/'RESULTS_EXP3.md',text);files.append('RESULTS_EXP3.md')

    exp4=tables['exp4_token_af']
    anchor=dict(ell=20,N=20,cmax=2,actual_L_hit=10)
    emu=_one(exp4,backend=EMU,**anchor)
    sgx=_one(exp4,backend=SGX,**anchor)
    if not isinstance(emu['policy_token_median_ms'],float) or emu['policy_token_median_ms']<=0:
        raise ValueError('invalid Exp4 comparison denominator')
    emu_exact=next(r['median'] for r in summaries[('Exp4',EMU)]
                   if r['configuration_id']==emu['configuration_id'] and
                      r['metric']=='policy_token_ns')
    sgx_exact=next(r['median'] for r in summaries[('Exp4',SGX)]
                   if r['configuration_id']==sgx['configuration_id'] and
                      r['metric']=='policy_token_ns')
    ratio=sgx_exact/emu_exact
    rows=loaded['cohorts'][('Exp4',EMU)]['rows']+loaded['cohorts'][('Exp4',SGX)]['rows']
    same=sum(r['metrics']['same_context_equal'] is True for r in rows)
    collisions=sum(r['metrics']['cross_context_equal_observed'] is True for r in rows)
    if same!=len(rows):raise ValueError('same-context check failed')
    write_json(bundle/'summary'/'EXP4_CONTEXT_OBSERVATIONS.json',
        dict(analysis_schema=ANALYSIS_SCHEMA,observations=len(rows),
             same_context_equal_count=same,cross_context_collision_count=collisions,
             empirical_collision_rate=collisions/len(rows),
             interpretation='sample observation, not an unlinkability proof'))
    text=_paper_intro('Exp4','separate EMULATED_TEST and REAL_SGX_DEBUG_FEASIBILITY cohorts')+(
        '## Research question\n\nWhat tokenization and AF costs are observed '
        'under the two recorded deployment profiles?\n\n'
        '## Experimental variables\n\nNine selected configurations per backend '
        'vary policy/user batch size, ell, N, cmax, and hit regime. The '
        'backend cohorts are summarized and plotted separately.\n\n'
        '## Observed result\n\nFor matched ell=20, N=20, cmax=2 and actual '
        f'L_hit=10, policy-token medians are {emu["policy_token_median_ms"]:.3f} '
        f'ms (EMULATED) and {sgx["policy_token_median_ms"]:.3f} ms (real SGX). '
        f'The observed deployment-profile ratio is {ratio:.2f}.\n\n'
        '## Quantitative evidence\n\nThe cited configuration IDs are '
        f'`{emu["configuration_id"]}` and `{sgx["configuration_id"]}`. '
        f'Same-context token equality held in {same}/{len(rows)} observations. '
        f'Cross-context equality was observed {collisions}/{len(rows)} times '
        f'({100*collisions/len(rows):.1f}% empirical rate).\n\n'
        '## Interpretation\n\nThe ratio includes all differences between '
        'these deployment profiles, including service, RPC, serialization, '
        'and instrumentation. RPC receive overlaps enclave computation; '
        'its displayed duration is not added to enclave total.\n\n'
        '## Boundary / caveat\n\n'+SGX_NOTE+' The finite contextual-token '
        'observations do not establish anonymity or unlinkability. '
        'The ratio is not isolated SGX hardware overhead.\n\n'
        'Sources: [Exp4 table](../tables/TABLE_EXP4_TOKEN_AF.md), '
        '[machine summary](../summary/EXP4_STATISTICS.csv), '
        '[context observations](../summary/EXP4_CONTEXT_OBSERVATIONS.json).\n')
    write_text(paper/'RESULTS_EXP4.md',text);files.append('RESULTS_EXP4.md')

    exp5=tables['exp5_scaling']
    threshold=[r for r in exp5 if r['policy_shape']=='threshold']
    a=min((r for r in threshold if r['N']==5),key=lambda r:r['actual_J'])
    b=min((r for r in threshold if r['N']==40),key=lambda r:r['actual_J'])
    diff=json.loads((bundle/'summary'/'EXP5_REQUESTED_ACTUAL_J.json').read_text())
    text=_paper_intro('Exp5','REAL_SGX_DEBUG_FEASIBILITY')+(
        '## Research question\n\nHow do actual AF candidates and '
        'reconstruction width relate to Transform and request E2E latency?\n\n'
        '## Experimental variables\n\nN={5,10,20,40}, requested candidate '
        'tiers, AND/threshold/repeated policy shapes, and recorded actual '
        'J, k, and tI. All primary candidate axes use actual J.\n\n'
        '## Observed result\n\nFor the smallest actual-J threshold '
        f'configurations at N=5 and N=40, E2E medians are '
        f'{a["E2E_median_ms"]:.3f} and {b["E2E_median_ms"]:.3f} ms; '
        f'actual J is {a["actual_J"]} and {b["actual_J"]}, respectively.\n\n'
        '## Quantitative evidence\n\nThe cited configuration IDs are '
        f'`{a["configuration_id"]}` and `{b["configuration_id"]}`. '
        f'Requested and actual J differ in {diff["differing_sample_count"]} '
        'of 320 samples; both values remain in the machine summary. '
        'CSP pairing count equals 1+tI for every sample.\n\n'
        '## Interpretation\n\nThe figures show within-system associations '
        'among candidate size, reconstruction structure, and observed '
        'latency. N and J vary together in the cited contrast.\n\n'
        '## Boundary / caveat\n\n'+SGX_NOTE+' These descriptive observations are '
        'not an asymptotic complexity result. E2E and stage durations are '
        'shown as separate measurements, not an additive decomposition.\n\n'
        'Sources: [Exp5 table](../tables/TABLE_EXP5_SCALING.md), '
        '[machine summary](../summary/EXP5_STATISTICS.csv), '
        '[requested/actual J audit](../summary/EXP5_REQUESTED_ACTUAL_J.csv).\n')
    write_text(paper/'RESULTS_EXP5.md',text);files.append('RESULTS_EXP5.md')

    synthesis=(
        '# Cross-experiment Results synthesis\n\n'
        'Exp1 supplies within-system operation counts and occurrence-regime '
        'latency distributions. Exp3 supplies canonical byte accounting for '
        'the same MYABE-08 construction, using an EMULATED_TEST storage '
        'cohort. Exp4 keeps the EMULATED_TEST and real SGX DEBUG feasibility '
        'profiles separate while recording tokenization and AF costs. Exp5 '
        'uses actual candidate and reconstruction counts for Transform and '
        'request-level observations. These pieces describe different '
        'measurements; they are not a competing-scheme benchmark.\n\n'
        'Recommended core figures are selected for research-question coverage '
        'and nonredundancy, with all candidate figures and their source data '
        'retained in the bundle.\n\n'
        +SGX_NOTE+' Formal status: CANDIDATE — FORMAL PROOF OPEN.\n')
    write_text(paper/'RESULTS_SYNTHESIS.md',synthesis);files.append('RESULTS_SYNTHESIS.md')
    limits=(
        '# Limitations for Results\n\n'
        'These controlled measurements verify implemented behavior, observed '
        'cost, and selected negative cases. They do not constitute a '
        'selective-CPA proof, anonymity reduction, collusion proof, '
        'revocation theorem, or side-channel-resistance result. Formal status '
        'remains CANDIDATE — FORMAL PROOF OPEN.\n\n'
        +SGX_NOTE+' The enclave is DEBUG. The platform TCB is OUT_OF_DATE; '
        'strict RA2 remains blocked. Production stable-key provisioning, '
        'persistent SGX state, hardware anti-rollback, trusted time, '
        'production remote current-head, and a release enclave are absent.\n\n'
        'For the same user and CT, W=T0q/T_A remains stable across requests; '
        'this is known linkability. Finite same-context equality and '
        'cross-context collision observations do not establish full '
        'anonymity or unlinkability. Exp7 supplied an earlier validated '
        'privacy/correctness gate, not a formal Phase 5A scaling dataset. '
        'Exp6 similarly supplied a revocation correctness gate, not a '
        'formal revocation scaling experiment.\n\n'
        'Exp2 remains BLOCKED_COMMON_BACKEND. No Charm/MNT224 versus '
        'py_ecc/BLS12-381 timing comparison is made. One run and three '
        'contiguous blocks per latency configuration limit inference; '
        'therefore no inferential confidence intervals or significance '
        'tests are reported. All raw samples remain in the analysis.\n')
    write_text(paper/'LIMITATIONS_FOR_RESULTS.md',limits);files.append('LIMITATIONS_FOR_RESULTS.md')
    return files


def _quality_text(loaded: dict, figure_ids: list[str], tables: dict,
                  lint: dict) -> str:
    ids=', '.join('`'+x+'`' for x in loaded['excluded_superseded_run_ids'])
    lines=['# Phase 5B analysis quality', '',
        'Input evidence: `PHASE5A_DATA_QUALITY.md` and the five frozen '
        '`revalidated-v2` dataset manifests. All 19 run validations and '
        'five cohort validations passed before the analysis source was added. '
        'The analysis loader rechecks frozen run indices, source hashes, '
        'schema, per-configuration coverage, provenance, and trust labels '
        'while explicitly pinning the recorded benchmark code-tree hash.', '',
        '| Cohort | Configurations | Measured rows | Failed |',
        '| --- | ---: | ---: | ---: |']
    for (exp,backend),item in loaded['cohorts'].items():
        lines.append(f'| {exp}/{backend} | {len(item["configuration_ids"])} | '
                     f'{len(item["rows"])} | 0 |')
    lines += ['',f'Total: {loaded["sample_count"]} rows. '
        'Excluded superseded runs: '
        f'{loaded["excluded_superseded_runs_count"]}; IDs: {ids}. '
        'They are absent from all summaries, plots, and tables.', '',
        'Statistical policy: all raw observations retained; per-configuration '
        'n, min, linear-interpolated Q1, median, Q3, mean, population std, '
        'p90, p95, and max. No trimming, winsorization, IQR deletion, or '
        'outlier exclusion. No p-value search. Main latency center is the '
        'median; p95 accompanies it. Exp3 uses one canonical artifact per '
        'configuration and no latency inference.', '',
        'CI policy: no inferential CI is reported. Each latency configuration '
        'has one run and only three contiguous blocks; these do not support '
        'a reliable independent-run cluster bootstrap. The deterministic '
        'block-bootstrap primitive is unit tested but deliberately unused '
        'in paper estimates.', '',
        'Missing-field policy: required observed durations and pairing '
        'counts were present and positive. EMULATED enclave/RPC fields and '
        'non-Exp4 user-batch fields remain explicitly NOT_OBSERVED. No '
        'missing observation was imputed. All duration units remain ns '
        'in machine summaries; presentation figures convert to ms. '
        'Requested and actual J remain separate.', '',
        'Trust policy: real SGX rows remain DEBUG feasibility with QVL '
        'OUT_OF_DATE and strict RA2 blocked. EMULATED_TEST remains a separate '
        'cohort. SGX captions and table footnotes disclose this boundary.', '',
        f'Generated figures: {len(figure_ids)} candidate figures, each PNG '
        'and PDF with figure-data CSV and metadata JSON. Generated paper '
        f'tables: {len(tables)}, each with machine table-data CSV. '
        'The recommended core set is selected by research-question coverage, '
        'not favorable direction. RPC receive/enclave durations are not '
        'summed as independent components.', '',
        f'Claim lint: {lint["status"]}, {lint["scanned_files"]} paper files '
        f'scanned, {len(lint["hits"])} forbidden phrase hits. '
        'Security and formal-proof limitations remain explicit.', '']
    return '\n'.join(lines)


def generate_all(*, output_root: Path = OUTPUT_ROOT) -> Path:
    loaded=load_frozen()
    code_hash=analysis_code_hash()
    analysis_id,bundle=new_analysis_dir(output_root)
    write_json(bundle/'validation'/'input_validation.json',dict(
        status='PASS',analysis_schema=ANALYSIS_SCHEMA,
        included_cohorts=[dict(experiment=e,backend=b,
            runs=len(loaded['cohorts'][(e,b)]['run_ids']),
            rows=len(loaded['cohorts'][(e,b)]['rows'])) for e,b in COHORTS],
        excluded_superseded_run_ids=loaded['excluded_superseded_run_ids'],
        specification_sha256=SPEC_HASH,
        benchmark_code_sha256='639f1c66c3a985fa24a81e863ab6db19038b9cbb1e36873d415de20f677ffbef'))
    summaries=produce_summaries(bundle,loaded,code_hash)
    tables=produce_tables(bundle,loaded,summaries)
    figures=produce_figures(bundle,loaded,summaries,code_hash)
    paper=produce_paper(bundle,loaded,tables,summaries,figures)
    lint=claim_lint(bundle/'paper')
    write_json(bundle/'validation'/'claim_lint.json',lint)
    if lint['status']!='PASS':raise ValueError('paper claim lint failed')
    write_text(bundle/'validation'/'PHASE5B_ANALYSIS_QUALITY.md',
               _quality_text(loaded,figures,tables,lint))
    # No benchmark input, including a superseded file, is altered.
    for relative,expected in loaded['input_hashes'].items():
        if sha256_file(REPO/relative)!=expected:
            raise ValueError('frozen raw input changed during analysis')
    outputs={str(p.relative_to(bundle)):sha256_file(p) for p in sorted(bundle.rglob('*'))
             if p.is_file()}
    write_json(bundle/'analysis_manifest.json',dict(
        analysis_schema=ANALYSIS_SCHEMA,analysis_id=analysis_id,
        created_utc=datetime.now(timezone.utc).isoformat(),status='COMPLETE',
        input_dataset_manifests={f'{e}/{b}':c['manifest_sha256']
                                 for (e,b),c in loaded['cohorts'].items()},
        input_hashes=loaded['input_hashes'],
        excluded_superseded_run_ids=loaded['excluded_superseded_run_ids'],
        analysis_code_sha256=code_hash,spec_sha256=SPEC_HASH,
        environment_fingerprint=ENVIRONMENT_HASH,
        benchmark_code_sha256='639f1c66c3a985fa24a81e863ab6db19038b9cbb1e36873d415de20f677ffbef',
        trust_cohorts=['EMULATED_TEST','REAL_SGX_DEBUG_FEASIBILITY'],
        statistics_policy='all samples; median/IQR/p95; no inferential CI; no outlier removal',
        ci_policy='NO_INFERENTIAL_CI_ONE_RUN_THREE_CONTIGUOUS_BLOCKS',
        plot_version='MYABE08-PLOT-V1',figures=figures,
        tables=sorted(tables),paper_files=paper,output_hashes=outputs))
    return bundle


def verify_bundle(bundle: Path) -> dict:
    bundle=Path(bundle)
    manifest=json.loads((bundle/'analysis_manifest.json').read_text())
    if manifest.get('status')!='COMPLETE' or manifest.get('analysis_schema')!=ANALYSIS_SCHEMA:
        raise ValueError('incomplete analysis bundle')
    if manifest['analysis_code_sha256']!=analysis_code_hash():
        raise ValueError('analysis source changed')
    for relative,expected in manifest['input_hashes'].items():
        if sha256_file(REPO/relative)!=expected:
            raise ValueError('input hash changed')
    for relative,expected in manifest['output_hashes'].items():
        if sha256_file(bundle/relative)!=expected:
            raise ValueError('analysis output changed')
    actual={str(p.relative_to(bundle)) for p in bundle.rglob('*') if p.is_file()}
    if actual != set(manifest['output_hashes'])|{'analysis_manifest.json'}:
        raise ValueError('unexpected or missing analysis output')
    lint=claim_lint(bundle/'paper')
    if lint['status']!='PASS':raise ValueError('claim lint failed')
    return dict(status='PASS',analysis_id=manifest['analysis_id'],
                outputs=len(manifest['output_hashes']),
                figures=len(manifest['figures']),tables=len(manifest['tables']))


def compare_bundles(first: Path,second: Path) -> dict:
    verify_bundle(first);verify_bundle(second)
    first=Path(first);second=Path(second)
    comparable=[]
    for folder in ('summary','tables','paper','figures'):
        for path in sorted((first/folder).iterdir()):
            if folder=='figures' and not (path.name.endswith('_data.csv') or
                                           path.name.endswith('_metadata.json') or
                                           path.name=='recommended_core_set.json'):
                continue
            comparable.append(str(path.relative_to(first)))
    for relative in comparable:
        if sha256_file(first/relative)!=sha256_file(second/relative):
            raise ValueError('semantic analysis rerun differs: '+relative)
    return dict(status='PASS',semantic_files_compared=len(comparable),
                policy='statistics, figure data/specification, tables and paper text byte-identical; rendered PDF/PNG excluded')
