"""Small read-only checks for the frozen Visual Review data selections."""
from core.myabe08.analysis.visual_review.__main__ import (
    ROOT, rows_for, source_data, sources_for, validate_inputs,
)


def test_visual_review_validates_exact_frozen_inputs():
    result = validate_inputs()
    assert result['phase5a_cohorts'] == 5
    assert result['phase5b']['status'] == result['phase5c']['status'] == 'PASS'
    assert set(result['phase5c_runs']) == {'Exp6', 'Exp7'}


def test_visual_review_figures_use_canonical_numbers():
    paths, data = source_data()
    assert all(str(p).startswith(str(ROOT)) for p in paths.values())
    e4 = rows_for('07', data)
    assert len(e4) == 2
    assert {r['policy_token_median_ms'] for r in e4} == {'1.968', '4.748'}
    assert len(rows_for('02', data)) == 16
    assert len(rows_for('05', data)) == 30
    assert len(rows_for('13', data)) == 5
    assert len(rows_for('18', data)) == 8
    assert len(rows_for('19', data)) == 5
    assert all(r['FinalDec_pairings'] == 0 for r in rows_for('04', data))
    assert any(p.name == 'LIMITATIONS_FOR_RESULTS.md' for p in sources_for('21', paths))


def test_visual_review_storage_components_are_mutually_exclusive():
    _, data = source_data()
    for r in rows_for('06', data):
        total = sum(int(r[k]) for k in ('CT_core_bytes', 'AF_bytes',
            'header_bytes', 'DEM_bytes', 'publication_bytes'))
        assert total == int(r['CT_total_bytes'])
