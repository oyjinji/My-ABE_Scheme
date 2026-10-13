"""No crypto vectors here: test explicit unavailability and import boundaries."""

import importlib
import inspect
import os
from pathlib import Path
import subprocess
import sys

import pytest

from core.myabe08 import (
    BENCHMARK_READY, EMULATED_TEE_PROFILE, FABEO_COMPAT_PROFILE,
    IMPLEMENTATION_STATUS, SECURITY_PROFILE_BLS12_381,
    EmulatedAnonymousAuthorizationEnclave,
)
from core.myabe08.legacy import LegacyMyABE08 as MyABE08
from core.myabe08.encoding import decode, decode_fixed_rows, encode, encode_fixed_rows
from core.myabe08.errors import AlgorithmNotImplementedError, BackendNotImplementedError
from core.myabe08.errors import UnsupportedProfileError
from core.myabe08.lsss import policy_encode
from core.myabe08.metrics import AFMetrics, OperationCounts, TEEMetrics, TransformMetrics
from core.myabe08.profile import PAIRING_PROFILES, TEE_PROFILES, SGX_DEBUG_GRAMINE_V1
from core.myabe08.state import commit_ack


def test_package_import_without_crypto_or_historical_imports():
    root = Path(__file__).resolve().parents[4]
    env = dict(os.environ, PYTHONPATH=str(root / "src"), PYTHONDONTWRITEBYTECODE="1")
    script = """
import importlib, pkgutil, sys
import core.myabe08 as p
for item in pkgutil.iter_modules(p.__path__):
    # Host-only operational facade intentionally imports crypto transports;
    # preserve the original lightweight scaffold import boundary here.
    if item.name not in ('tests', 'public'):
        importlib.import_module(p.__name__ + '.' + item.name)
for prefix in ('charm', 'py_ecc', 'cryptography', 'core.fxabe_rev',
               'core.fxabe_05_3_exp', 'core.fxdacp', 'core.dacp', 'core.fabeo22cp'):
    assert not any(n == prefix or n.startswith(prefix + '.') for n in sys.modules), prefix
assert p.IMPLEMENTATION_STATUS == 'PHASE_4EF_PUBLIC_TEST_FACADE'
assert not p.BENCHMARK_READY
"""
    subprocess.run([sys.executable, "-c", script], cwd=str(root), env=env,
                   check=True, capture_output=True, text=True)


def test_profile_axes_are_separate_and_neither_pairing_profile_is_ready():
    assert set(PAIRING_PROFILES) == {SECURITY_PROFILE_BLS12_381, FABEO_COMPAT_PROFILE}
    assert set(TEE_PROFILES) == {EMULATED_TEE_PROFILE, SGX_DEBUG_GRAMINE_V1}
    assert not set(PAIRING_PROFILES) & set(TEE_PROFILES)
    assert all(p.implementation_status == "NOT_IMPLEMENTED" for p in PAIRING_PROFILES.values())
    assert not TEE_PROFILES[EMULATED_TEE_PROFILE].hardware_isolation
    assert TEE_PROFILES[SGX_DEBUG_GRAMINE_V1].hardware_isolation
    assert 'DEBUG' in TEE_PROFILES[SGX_DEBUG_GRAMINE_V1].boundary
    assert IMPLEMENTATION_STATUS == "PHASE_4EF_PUBLIC_TEST_FACADE"
    assert not BENCHMARK_READY


@pytest.mark.parametrize("kwargs", [
    {"pairing_profile_id": "AUTO"},
    {"pairing_profile_id": EMULATED_TEE_PROFILE},
    {"pairing_profile_id": "BLS12-381"},  # no implicit alias fallback
    {"tee_profile_id": SECURITY_PROFILE_BLS12_381},
    {"tee_profile_id": "SGX"},
])
def test_unsupported_or_cross_axis_profile_fails_closed(kwargs):
    with pytest.raises(UnsupportedProfileError):
        MyABE08(**kwargs)


@pytest.mark.parametrize("profile", [SECURITY_PROFILE_BLS12_381, FABEO_COMPAT_PROFILE])
def test_installed_library_does_not_enable_unimplemented_setup(profile):
    scheme = MyABE08(pairing_profile_id=profile)
    with pytest.raises(BackendNotImplementedError, match="scheme backend integration is not implemented"):
        scheme.setup(security_parameter=128, c_max=8, provisioning_channel=None)


def _placeholder_call(call):
    """Sentinel input exercises stubs only, never simulates a crypto vector."""
    kwargs = {name: None for name, parameter in inspect.signature(call).parameters.items()
              if parameter.default is inspect.Parameter.empty}
    with pytest.raises(NotImplementedError):
        call(**kwargs)


@pytest.mark.parametrize("method", [
    "setup", "keygen", "encrypt", "rev", "rev_state_upt",
    "tee_authorize", "transform", "final_dec",
])
def test_all_main_algorithms_explicitly_unimplemented(method):
    _placeholder_call(getattr(MyABE08(), method))


@pytest.mark.parametrize("call", [
    EmulatedAnonymousAuthorizationEnclave().provision_user,
    EmulatedAnonymousAuthorizationEnclave().tokenize_policy,
    EmulatedAnonymousAuthorizationEnclave().rev_state_upt,
    EmulatedAnonymousAuthorizationEnclave().authorize,
    policy_encode, commit_ack,
])
def test_internal_placeholders_never_return_success_or_miss(call):
    _placeholder_call(call)


def test_unavailable_operations_do_not_manufacture_metrics():
    metrics = AFMetrics()
    assert metrics.status == "NOT_EXECUTED"
    assert metrics.query_ns is None
    assert metrics.decoded_payloads is None
    for counter in (OperationCounts(), TEEMetrics().ops, TransformMetrics().csp_ops):
        assert all(value is None for value in vars(counter).values())


def test_enclave_does_not_inherit_scheme_or_claim_hardware_support():
    assert not issubclass(EmulatedAnonymousAuthorizationEnclave, MyABE08)
    enclave = EmulatedAnonymousAuthorizationEnclave()
    assert enclave.profile.boundary == "software emulation only"
    from core.myabe08.state import UnavailableCurrentStateCoordinator
    assert isinstance(enclave.coordinator, UnavailableCurrentStateCoordinator)
    with pytest.raises(UnsupportedProfileError):
        EmulatedAnonymousAuthorizationEnclave(profile="SGX")


def test_protocol_contracts_have_resolvable_type_annotations():
    from typing import get_type_hints
    for name in ("types", "scheme", "tee", "af", "credential", "state", "crypto", "lsss", "algebra"):
        module = importlib.import_module("core.myabe08." + name)
        for obj in vars(module).values():
            if inspect.isclass(obj) and obj.__module__ == module.__name__:
                get_type_hints(obj)
                for method in vars(obj).values():
                    if inspect.isfunction(method):
                        get_type_hints(method)
