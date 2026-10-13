"""Shape and fail-closed tests; Python introspection is not a secrecy proof."""
from dataclasses import fields
import inspect

import pytest

from core.myabe08.errors import StateSynchronizationError
from core.myabe08.real_tee.providers import (SgxDebugBootstrapBundle,
    UnavailableTrustedCurrentHeadProvider, UnavailableTrustedTimeProvider)
from core.myabe08.real_tee import service


def test_test_bundle_has_no_kgc_msk_or_du_recovery_field():
    names = {item.name for item in fields(SgxDebugBootstrapBundle)}
    assert {'sys_id', 'k_tok', 'k_rev', 'sk_cap', 'k_seal',
            'k_state', 'k_head', 'profile_id'} == names
    assert names.isdisjoint({'alpha', 'a', 'msk', 'sk_kgc', 'rk',
                             'mu', 'k0', 'mu_q', 'delta_q'})
    for item in fields(SgxDebugBootstrapBundle):
        if item.name.startswith('k_') or item.name == 'sk_cap':
            assert item.repr is False


def test_unconfigured_trusted_ports_fail_closed():
    with pytest.raises(StateSynchronizationError):
        UnavailableTrustedCurrentHeadProvider().authorization_transaction()
    with pytest.raises(StateSynchronizationError):
        UnavailableTrustedTimeProvider().now()


def test_service_has_no_historical_or_fixture_runtime_import():
    source = inspect.getsource(service)
    for forbidden in ('core.fxabe_05_3_exp', 'core.fxabe_rev',
                      'core.fxdacp', 'core.myabe08.tests', 'pickle',
                      'eval(', 'exec('):
        assert forbidden not in source
