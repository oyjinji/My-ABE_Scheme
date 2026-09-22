import sys
from pathlib import Path

import pytest
from charm.toolbox.pairinggroup import PairingGroup


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def group():
    return PairingGroup("MNT224")

