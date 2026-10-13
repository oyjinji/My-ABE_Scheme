"""Phase 5B statistical, provenance, plotting, and table gates."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from core.myabe08.analysis.core import (analysis_code_hash,
    cluster_bootstrap_median, describe, load_frozen, quantile)
from core.myabe08.analysis.plots import numeric_figure
from core.myabe08.analysis.products import produce_figures, produce_summaries, produce_tables
from core.myabe08.analysis.report import claim_lint


def test_descriptive_quantiles_and_no_outlier_drop():
    values=[1,2,3,1000]
    result=describe(values)
    assert result['n']==4 and result['max']==1000
    assert result['q1']==1.75 and result['median']==2.5
    assert result['q3']==252.25 and result['p95']==pytest.approx(850.45)
    assert quantile([0,10,20,30],.95)==pytest.approx(28.5)


def test_block_bootstrap_primitive_is_deterministic_and_bounded():
    first=cluster_bootstrap_median([[1,2],[9,10]],seed=42,replicates=200)
    second=cluster_bootstrap_median([[1,2],[9,10]],seed=42,replicates=200)
    assert first==second and 1<=first[0]<=first[1]<=10
    with pytest.raises(ValueError):
        cluster_bootstrap_median([[1,2]],replicates=200)


def test_frozen_grouping_backend_isolation_and_actual_j():
    loaded=load_frozen()
    assert loaded['sample_count']==1030
    assert loaded['excluded_superseded_runs_count']==10
    emu=loaded['cohorts'][('Exp4','EMULATED_TEE_PROFILE')]
    sgx=loaded['cohorts'][('Exp4','SGX_DEBUG_GRAMINE_V1')]
    assert len(emu['rows'])==len(sgx['rows'])==180
    assert {r['backend'] for r in emu['rows']}=={'EMULATED_TEE_PROFILE'}
    assert {r['backend'] for r in sgx['rows']}=={'SGX_DEBUG_GRAMINE_V1'}
    exp5=loaded['cohorts'][('Exp5','SGX_DEBUG_GRAMINE_V1')]['rows']
    assert sum(r['variables']['requested_J']!=r['variables']['actual_J']
               for r in exp5)==20


def test_paper_table_reproduces_machine_summary():
    loaded=load_frozen()
    with TemporaryDirectory() as directory:
        root=Path(directory)
        (root/'summary').mkdir();(root/'tables').mkdir()
        summaries=produce_summaries(root,loaded,analysis_code_hash())
        tables=produce_tables(root,loaded,summaries)
        row=tables['exp1_results'][0]
        item=next(x for x in summaries[('Exp1','SGX_DEBUG_GRAMINE_V1')]
                  if x['configuration_id']==row['configuration_id'] and
                     x['metric']=='encrypt_ns')
        assert row['Encrypt_median_ms']==round(item['median']/1_000_000,3)
        with (root/'tables'/'table_exp1_results_data.csv').open(newline='') as source:
            serialized=list(csv.DictReader(source))
        assert serialized[0]['configuration_id']==row['configuration_id']
        assert float(serialized[0]['Encrypt_median_ms'])==row['Encrypt_median_ms']
        assert json.loads((root/'summary'/'EXP5_REQUESTED_ACTUAL_J.json').read_text())[
            'differing_sample_count']==20


def test_plot_has_nonempty_vector_raster_source_and_units():
    rows=[dict(x=1,median=1.0,p95=1.4,series='A',configuration_id='c1'),
          dict(x=2,median=2.0,p95=2.4,series='A',configuration_id='c2')]
    with TemporaryDirectory() as directory:
        root=Path(directory)
        numeric_figure(root,'test_plot',rows,x='x',y='median',
            title='test',xlabel='size',ylabel='Latency (ms)',series='series',
            p95='p95',metadata=dict(source_datasets=['frozen'],filter='all',
                grouping='series',statistic='median',unit='ms',script='test',
                analysis_code_sha256='test',caption='test'))
        for suffix in ('.png','.pdf'):
            assert (root/('test_plot'+suffix)).stat().st_size>100
        data=list(csv.DictReader((root/'figure_test_plot_data.csv').open()))
        assert len(data)==2 and set(data[0])>={'x','median','p95'}
        metadata=json.loads((root/'figure_test_plot_metadata.json').read_text())
        assert metadata['x_field']=='x' and metadata['unit']=='ms'


def test_complete_figures_keep_backend_distributions_and_traceability():
    loaded=load_frozen()
    with TemporaryDirectory() as directory:
        root=Path(directory)
        (root/'summary').mkdir();(root/'figures').mkdir()
        summaries=produce_summaries(root,loaded,analysis_code_hash())
        figures=produce_figures(root,loaded,summaries,analysis_code_hash())
        assert len(figures)==23
        for name in ('Fig_Exp4_I_Emulated_Distribution',
                     'Fig_Exp4_J_SGX_Distribution'):
            data=list(csv.DictReader((root/'figures'/f'figure_{name}_data.csv').open()))
            assert len(data)==20
            assert len({row['backend'] for row in data})==1
            metadata=json.loads((root/'figures'/f'figure_{name}_metadata.json').read_text())
            assert metadata['unit']=='ms'
            assert metadata['script']=='core.myabe08.analysis.products.produce_figures'
            assert len(metadata['source_dataset_manifests'])==1


def test_claim_lint_rejects_unsupported_phrase():
    with TemporaryDirectory() as directory:
        root=Path(directory)
        (root/'one.md').write_text('Observed latency only.\n')
        assert claim_lint(root)['status']=='PASS'
        (root/'two.md').write_text('This outperforms FABEO.\n')
        assert claim_lint(root)['status']=='FAIL'
