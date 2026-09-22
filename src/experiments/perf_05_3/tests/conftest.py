import sys
from pathlib import Path

import pytest
from charm.toolbox.pairinggroup import PairingGroup

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture(scope="session")
def group():
    return PairingGroup("MNT224")
