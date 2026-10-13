"""Opt-in real Gramine SGX Phase 5C exact-set and adversarial smoke."""
import os
from pathlib import Path
import secrets

import pytest

if os.environ.get('MYABE08_RUN_SGX_PHASE5C')!='1':
    pytest.skip('set MYABE08_RUN_SGX_PHASE5C=1 for real Phase 5C test',
                allow_module_level=True)

from core.myabe08.experiments.phase5c_collect import (
    _adversarial,_context,_lifecycle,_ready_scheme,_register,_service,_update)
from core.myabe08.experiments.workloads import generate_workload
from core.myabe08.revocation import REVOKE,ACTIVATE


@pytest.mark.sgx
@pytest.mark.real_sgx_phase5c
def test_real_exact_revset_and_fail_closed_faults(tmp_path):
    build=Path(os.environ.get('MYABE08_SGX_DEBUG_BUILD_DIR',
                              '/tmp/myabe08-phase5c-build'))
    with _service(build) as (client,log,temp):
        scheme,environment,trust=_ready_scheme(client,build,tmp_path/'kgc')
        assert trust['QVLResult']=='SGX_QL_QV_RESULT_OUT_OF_DATE'
        assert environment['sgx']['build_directory']==str(build.resolve())
        assert environment['sgx']['mrenclave']==scheme.metadata['MRENCLAVE']
        spec=generate_workload('W-SINGLE',17)
        active_uid,active_user,active_holder=_register(scheme,spec)
        spare_uid,spare_user,spare_holder=_register(scheme,spec)
        ct=scheme.Encrypt(message=b'phase5c',policy=spec.policy(),
            context=_context(scheme,spec),data_id=secrets.token_bytes(16))
        before=client.observe_test_state()
        assert before['revset_count']==0
        assert before['registration_state_count']==2
        lifecycle,replay_update,replay_ack=_lifecycle(scheme,client,
            spare_uid,spare_user,spare_holder,ct)
        assert lifecycle['historical_unconsumed_auth_valid']
        assert client.observe_test_state()['revset_count']==0
        negatives=_adversarial(scheme,client,spare_uid,active_uid,
            active_user,active_holder,ct,replay_update,replay_ack)
        assert all(negatives.values())
        client.stop_test_service()
        assert 'TEST-UID-' not in log.read_text(errors='replace')
