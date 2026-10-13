"""One real Gramine DEBUG, QVL-checked Phase 4F harness smoke."""
import json
import os
from pathlib import Path
import subprocess
import time

import pytest

if os.environ.get('MYABE08_RUN_SGX_EXPERIMENT') != '1':
    pytest.skip('set MYABE08_RUN_SGX_EXPERIMENT=1 for real harness smoke',
                allow_module_level=True)

from core.myabe08.experiments.runner import run_smoke
from core.myabe08.experiments.storage import validate_run
from core.myabe08.profile import SGX_DEBUG_GRAMINE_V1
from core.myabe08.real_tee.client import SgxDebugClient

ROOT = Path(__file__).resolve().parents[5]
BUILD = Path(os.environ.get('MYABE08_SGX_DEBUG_BUILD_DIR',
                            '/tmp/myabe08-sgx-ra-probe'))


@pytest.mark.sgx
@pytest.mark.real_sgx_experiment_smoke
def test_real_sgx_exp4_harness_smoke(tmp_path):
    audit = json.loads((BUILD/'build_audit.json').read_text())
    assert audit['debug'] is True and audit['remote_attestation'] == 'dcap'
    log = tmp_path/'sgx-service.log'
    client = SgxDebugClient()
    with log.open('wb') as output:
        process = subprocess.Popen(('bash',str(ROOT/
            'src/core/myabe08/real_tee/gramine/run_sgx.sh')),
            cwd=ROOT,env=dict(os.environ,MYABE08_SGX_DEBUG_BUILD_DIR=str(BUILD)),
            stdout=output,stderr=subprocess.STDOUT)
        try:
            for _ in range(200):
                if process.poll() is not None:
                    pytest.fail('Gramine exited before harness readiness')
                try:
                    client.health(); break
                except (ConnectionError,OSError,TimeoutError):
                    time.sleep(.1)
            else:
                pytest.fail('Gramine not ready')
            result = run_smoke(('Exp4',), SGX_DEBUG_GRAMINE_V1,
                root=tmp_path/'runs', build_dir=BUILD, client=client,
                warmups=0, repetitions=1)
            assert result['status'] == 'COMPLETE'
            path = Path(result['run_path'])
            assert validate_run(path)['status'] == 'PASS'
            manifest = json.loads((path/'manifest.json').read_text())
            trust = manifest['trust_metadata']
            assert trust['QVLApiReturn'] == 0
            assert trust['CollateralExpirationStatus'] == 0
            assert trust['QVLResult'] == 'SGX_QL_QV_RESULT_OUT_OF_DATE'
            assert trust['StrictRA2'] == 'BLOCKED_BY_TCB_POLICY'
            assert trust['EnclaveDebug'] is True
            row = json.loads((path/'raw.jsonl').read_text().splitlines()[0])
            assert row['backend'] == SGX_DEBUG_GRAMINE_V1
            assert row['correctness_verified'] is True
            assert all(type(row['metrics'][name]) is int for name in (
                'host_pre_rpc_ns','rpc_send_ns','rpc_receive_ns','host_post_rpc_ns',
                'enclave_total_ns','credential_verify_ns','revset_lookup_ns',
                'tokenization_ns','rerandomization_ns','t0_pairing_ns',
                'cap_sign_ns','host_to_tee_bytes','tee_to_host_bytes'))
            assert row['counters']['tee_pairing_count'] == 1
            assert row['counters']['csp_pairing_count'] == 1 + row['variables']['actual_tI']
        finally:
            if process.poll() is None:
                try:
                    client.stop_test_service(); process.wait(timeout=10)
                except Exception:
                    process.terminate(); process.wait(timeout=10)
    assert 'SYNTHETIC-UID-' not in log.read_text(errors='replace')
