import random

import pytest
from charm.toolbox.pairinggroup import PairingGroup

from core.fxdacp import FXDACP


@pytest.fixture(scope="module")
def group():
    return PairingGroup("MNT224")


@pytest.fixture
def scheme(group):
    return FXDACP(group, rng=random.Random(20260721))
