"""Actual SGX quote-generation diagnostic; quote-view only parses bytes."""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time

import pytest

if os.environ.get('MYABE08_RUN_SGX_RA_PROBE') != '1':
    pytest.skip('set MYABE08_RUN_SGX_RA_PROBE=1 for real quote probe',
                allow_module_level=True)

from core.myabe08.real_tee.attestation import attestation_binding
from core.myabe08.real_tee.client import SgxDebugClient

ROOT=Path(__file__).resolve().parents[5]
BUILD=Path(os.environ.get('MYABE08_SGX_DEBUG_BUILD_DIR',
                          '/tmp/myabe08-sgx-ra-probe'))


@pytest.mark.sgx
def test_real_quote_generation_and_unverified_binding(tmp_path):
    audit=json.loads((BUILD/'build_audit.json').read_text())
    assert audit['remote_attestation']=='dcap'
    log=tmp_path/'gramine.log'
    with log.open('wb') as output:
        process=subprocess.Popen(('bash',str(ROOT/'src/core/myabe08/real_tee/gramine/run_sgx.sh')),
            cwd=ROOT,env=dict(os.environ,MYABE08_SGX_DEBUG_BUILD_DIR=str(BUILD)),
            stdout=output,stderr=subprocess.STDOUT)
        client=SgxDebugClient()
        try:
            for _ in range(200):
                if process.poll() is not None:
                    pytest.fail('DCAP Gramine enclave exited before readiness')
                try:
                    profile=client.profile_info()
                    break
                except (ConnectionError,OSError,TimeoutError):
                    time.sleep(.1)
            else:
                pytest.fail('DCAP Gramine enclave did not become ready')
            assert profile[6].hex()==audit['mrenclave']
            assert profile[8].value & 2
            sys_id=b'MYABE08-RA-PROBE'
            challenge=secrets.token_bytes(32)
            response=client.quote_diagnostic(sys_id,challenge)
            assert response[0]=='MYABE08-RA-QUOTE-UNVERIFIED', response[:2]
            public,report_data,quote=response[1:]
            assert len(quote)>432 and len(public)==32
            assert report_data==attestation_binding(sys_id,challenge,public)
            path=tmp_path/'public-quote.bin'
            path.write_bytes(quote)
            viewed=subprocess.run(('gramine-sgx-quote-view',str(path)),
                check=True,capture_output=True,text=True).stderr
            def field(name):
                match=re.search(r'^\s*'+re.escape(name)+r'\s*:\s*([0-9a-f]+)',
                                viewed,re.MULTILINE)
                assert match is not None
                return match.group(1)
            assert field('mr_enclave')==audit['mrenclave']
            assert field('mr_signer')==audit['mrsigner']
            assert field('report_data')==report_data.hex()
            assert int(field('attributes.flags')[:2],16)&2
            assert int(field('signature_size'))>0
            assert attestation_binding(sys_id,b'X'*32,public)!=report_data
            assert attestation_binding(sys_id,challenge,b'Y'*32)!=report_data
        finally:
            if process.poll() is None:
                try:
                    client.stop_test_service()
                    process.wait(timeout=10)
                except Exception:
                    process.terminate()
                    process.wait(timeout=10)
