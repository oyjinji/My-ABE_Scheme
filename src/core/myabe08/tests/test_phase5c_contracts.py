"""Phase 5C plan, state-accounting, and artifact contract gates."""
import json

import pytest

from core.myabe08.credential import CredentialVersionRegistry
from core.myabe08.experiments.phase5c import (RunWriter, TRUST_EXPECTED,
    make_plan, validate_plan, validate_run)
from core.myabe08.experiments.phase5c_collect import _exp7_inventory
from core.myabe08.experiments.provenance import code_manifest, environment_manifest
from core.myabe08.signing import new_private_key, public_key_bytes
from core.myabe08.types import Attribute, Validity
from core.myabe08.credential import issue_credential


def _plan(**changes):
    return make_plan(keygen_calibration_ns=500_000_000,
        update_calibration_ns=20_000_000,
        active_calibration_ns=2_000_000_000,**changes)


def test_full_plan_and_hash_are_frozen():
    plan=_plan()
    assert validate_plan(plan)
    assert plan['rl_grid']==[0,10,100,1000,5000]
    assert plan['n_reg_grid']==[100,1000,5000]
    assert plan['repetitions']==30 and plan['blocks']==3
    damaged=dict(plan,rl_grid=[0,10,100])
    with pytest.raises(ValueError,match='hash'):validate_plan(damaged)


def test_budget_reduction_preserves_named_dimensions():
    plan=make_plan(keygen_calibration_ns=5_000_000_000,
        update_calibration_ns=3_000_000_000,
        active_calibration_ns=10_000_000_000)
    assert plan['plan_kind']=='REDUCED_BALANCED_PLAN'
    assert plan['rl_grid']==[0,10,100,1000]
    assert plan['n_reg_grid']==[100,1000]
    assert validate_plan(plan)


def test_registry_logical_bytes_are_real_state_accounting():
    registry=CredentialVersionRegistry()
    empty=registry.logical_bytes()
    key=new_private_key()
    cred=issue_credential(key,b'phase5c-test','synthetic-uid',
        (Attribute('synthetic','label','a'),),Validity(100,2000),1,
        public_key_bytes(new_private_key()))
    registry.register(cred)
    assert registry.count()==1 and registry.logical_bytes()>empty


def test_transcript_inventory_discloses_known_w_without_values():
    inventory=_exp7_inventory()
    assert len(inventory['rows'])>=6
    assert any('stable same-user/same-CT W' in x for x in inventory['known_leakage'])
    assert 'private_key' not in json.dumps(inventory)


def test_immutable_writer_rejects_incomplete_measured_run(tmp_path):
    plan=_plan()
    writer=RunWriter('Exp6',plan,environment_manifest(),code_manifest(),
        dict(TRUST_EXPECTED),root=tmp_path)
    writer.append('ACTIVE_LOOKUP',rl_size=0,n_reg=1,block_id=0,
        sample_index=0,status='OK',expected='AUTHORIZED',actual='AUTHORIZED',
        metrics=dict(revset_lookup_ns=100))
    writer.evidence('canary_audit',dict(status='PASS',forbidden_value_hits=0))
    path=writer.finish()
    with pytest.raises((ValueError,OSError,KeyError)):
        validate_run(path)
