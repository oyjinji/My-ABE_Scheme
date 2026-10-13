"""Historical APIs cannot leak into the new protocol through imports/names."""

import ast
import inspect
from pathlib import Path

from core.myabe08.legacy import LegacyMyABE08 as MyABE08
from core.myabe08.tee import EmulatedAnonymousAuthorizationEnclave


def test_no_historical_import_or_tree_revocation_api_dependency():
    root = Path(__file__).resolve().parents[1]
    prohibited = {
        "KUNodes", "BinaryRevocationTree", "PrivacyKeyUpt", "RevKeyUpt",
        "privacy_key_upt", "rev_key_upt", "Cover", "PairingOPRF", "PrototypeOPRF",
    }
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.level <= 1, (path, node.module)
                assert not (node.module or "").startswith(("core.", "experiments.")), path
            if isinstance(node, ast.Import):
                assert all(not n.name.startswith(("core.", "experiments.")) for n in node.names), path
            if isinstance(node, ast.Name):
                assert node.id not in prohibited, (path, node.id)
            if isinstance(node, ast.Attribute):
                assert node.attr not in prohibited, (path, node.attr)
    public = {n for n, f in inspect.getmembers(MyABE08, inspect.isfunction)
              if not n.startswith("_")}
    assert public == {"setup", "keygen", "encrypt", "rev", "rev_state_upt",
                      "tee_authorize", "transform", "final_dec"}


def test_privacy_boundaries_in_callable_signatures():
    encrypt = inspect.signature(MyABE08.encrypt).parameters
    assert not {"msk", "ku", "rev_version", "revocation_epoch", "privacy_epoch"} & set(encrypt)
    for operation in (MyABE08.transform,):
        params = inspect.signature(operation).parameters
        assert not {"uid", "credential", "blob", "mu", "k0", "tk", "recovery_key"} & set(params)
    params = inspect.signature(EmulatedAnonymousAuthorizationEnclave.authorize).parameters
    assert "credential" in params and "possession" in params
    assert not {"attributes", "recovery_key", "msk", "alpha", "message"} & set(params)
