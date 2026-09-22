import pytest
from charm.toolbox.pairinggroup import PairingGroup

from core.fxabe_rev import FXABERev


@pytest.fixture(scope="module")
def group():
    return PairingGroup("MNT224")


@pytest.fixture
def prepared(group):
    scheme = FXABERev(group, user_capacity=8, scheme_seed=20260728)
    pp, msk = scheme.setup()
    return scheme, pp, msk
