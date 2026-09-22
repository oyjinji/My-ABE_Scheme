"""Shared fixtures for Global_Exp tests.

``python3 -m pytest`` from the repository root already puts the repo root on
``sys.path``; we also insert it defensively so the suite runs under plain
``pytest`` too.  One module-scoped pairing group is shared by all tests.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import pytest  # noqa: E402
from charm.toolbox.pairinggroup import PairingGroup  # noqa: E402


@pytest.fixture(scope="module")
def group():
    return PairingGroup("MNT224", secparam=512)
