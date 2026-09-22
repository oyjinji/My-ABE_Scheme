"""Fixtures for the script-plus-tests modules under src/benchmarks/.

Each ``test_dacp_*.py`` here doubles as a runnable script: its ``main()`` builds
its own inputs and calls the test functions directly. Those functions take
``tmp``, ``group``, ``codec`` and ``product`` as parameters, but nothing ever
defined them, so under pytest all 18 of them errored during setup.

These fixtures supply exactly what the matching ``main()`` supplies, so the
parameters mean under pytest what they already meant when run as a script:

    tmp      a temporary directory, as a Path
    group    PairingGroup("MNT224"), guarded as test_dacp_wire.main() guards it
    codec    WireCodec(group)
    product  the saved-and-reloaded product built by the catalog test

No new semantics are introduced here; if one of these looks wrong, the
authority is the ``main()`` at the bottom of the module that uses it.
"""

import pytest


@pytest.fixture
def tmp(tmp_path):
    """A temporary directory as a Path, as main()'s TemporaryDirectory() is."""
    return tmp_path


@pytest.fixture(scope="module")
def group():
    """PairingGroup("MNT224"), skipping if the wire backends are unavailable.

    test_dacp_wire.main() probes both AEAD/signature backends and returns early
    on RuntimeError; pytest.skip is the equivalent at fixture level.
    """
    from charm.toolbox.pairinggroup import PairingGroup

    from core.dacp.components import AESGCMEnvelope, Ed25519Signature

    try:
        AESGCMEnvelope()
        Ed25519Signature()
    except RuntimeError as exc:
        pytest.skip("wire tests skipped: {0}".format(exc))
    return PairingGroup("MNT224")


@pytest.fixture
def codec(group):
    """WireCodec over the shared MNT224 group."""
    from core.dacp.protocol import WireCodec

    return WireCodec(group)


@pytest.fixture
def product(tmp):
    """The product that marketplace main() passes to test_purchase.

    main() reuses one temporary directory across all three marketplace tests and
    threads the product from the first into the third. pytest gives every test
    in a module the same ``tmp`` instance, so building it here reproduces that
    arrangement.
    """
    import test_dacp_marketplace_scaffold

    return test_dacp_marketplace_scaffold.build_product(tmp)