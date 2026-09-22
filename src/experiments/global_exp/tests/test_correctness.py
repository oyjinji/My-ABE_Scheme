"""End-to-end correctness tests for the three Global_Exp scheme adapters.

Every test uses real Charm MNT224 pairing-group operations and a real,
fully-prepared scheme (setup, key issuance, revocation epoch).  Nothing is
mocked; the pair counter is the scheme's own ``_pair_counter``.
"""

import pytest

from charm.toolbox.pairinggroup import GT

from core.fabeo22cp import FABEO22CPABE
from core.fxabe_rev import FXABERev, TransformMetrics

from experiments.global_exp.src.adapters import create_adapter
from experiments.global_exp.src.common import derive_seed
from experiments.global_exp.src.workloads import build_workload

MS = 20260812
EPOCH = 1
PRIVACY_EPOCH = "privacy-1"


def _workload(l=8, user_attrs=8):
    return build_workload(MS, "test", derive_seed(MS, "test", l, user_attrs),
                          l, user_attrs, 0.5)


def _prepared(adapter, workload, seed=0):
    scheme = adapter.new_scheme(derive_seed(MS, "test", "scheme",
                                            workload.seed, seed))
    setup = adapter.setup(scheme, seed)
    prov = adapter.provision(scheme, setup["pk"], setup["msk"], workload,
                             "user-0", PRIVACY_EPOCH)
    scheme.state["tree"].register("user-1")
    scheme.rev("user-1", EPOCH)
    scheme.rev_key_upt(setup["pk"], EPOCH)
    ku = scheme.state["ku"][EPOCH]
    return scheme, setup, prov, ku


def _encrypt(adapter, scheme, setup, workload, seed=0):
    return adapter.encrypt(
        scheme, setup["pk"], setup["msk"], workload, PRIVACY_EPOCH, EPOCH,
        seed=derive_seed(MS, "test", "filter", workload.seed, seed),
    )


def test_fabeo22_direct_roundtrip(group):
    """The real FABEO22 scheme: setup/keygen/encrypt/decrypt round-trip."""
    scheme = FABEO22CPABE(group)
    pk, msk = scheme.setup()
    key = scheme.keygen(pk, msk, ["P0000", "P0001"])
    msg = group.init(GT, 4242)
    ct = scheme.encrypt(pk, msg, "(P0000 or P0001)")
    out = scheme.decrypt(pk, ct, key)
    assert out == msg
    assert len(ct["ct"]) == 2  # OR policy over 2 attrs -> 2 MSP rows


def test_fxabe_full_pipeline(group):
    """FXABE-Full: OPRF -> FX-ABF -> PStore -> ABE -> Transform -> FinalDec."""
    adapter = create_adapter("FXABE-Full", group)
    workload = _workload()
    scheme, setup, prov, ku = _prepared(adapter, workload)
    enc = _encrypt(adapter, scheme, setup, workload)
    tr = adapter.transform(scheme, setup["pk"], enc["ct"], prov["keys"], ku)
    assert tr["status"] == "ok"
    fd = adapter.final_dec(scheme, setup["pk"], tr["transformed"],
                           prov["keys"])
    assert fd["msg"] == workload.message_bytes


def test_fxabe_base_pipeline(group):
    """FXABE-Base: direct mapping, same real pairings + final_dec."""
    adapter = create_adapter("FXABE-Base", group)
    workload = _workload()
    scheme, setup, prov, ku = _prepared(adapter, workload)
    enc = _encrypt(adapter, scheme, setup, workload)
    tr = adapter.transform(scheme, setup["pk"], enc["ct"], prov["keys"], ku)
    assert tr["status"] == "ok"
    fd = adapter.final_dec(scheme, setup["pk"], tr["transformed"],
                           prov["keys"])
    assert fd["msg"] == workload.message_bytes


def test_revocation_blocks_revoked_user(group):
    """A user revoked at the ciphertext epoch cannot transform/decrypt.

    The active user must still decrypt correctly in the same epoch.
    """
    adapter = create_adapter("FXABE-Full", group)
    workload = _workload(l=8, user_attrs=8)
    scheme = adapter.new_scheme(derive_seed(MS, "test", "scheme",
                                            workload.seed))
    setup = adapter.setup(scheme, 0)
    prov_active = adapter.provision(scheme, setup["pk"], setup["msk"],
                                    workload, "user-0", PRIVACY_EPOCH)
    prov_revoked = adapter.provision(scheme, setup["pk"], setup["msk"],
                                     workload, "user-1", PRIVACY_EPOCH)
    # publish revocation epoch 1 with user-1 revoked
    scheme.rev("user-1", EPOCH)
    scheme.rev_key_upt(setup["pk"], EPOCH)
    ku = scheme.state["ku"][EPOCH]

    enc = _encrypt(adapter, scheme, setup, workload)
    # revoked user: path cover intersection is empty -> scheme returns None
    metrics = TransformMetrics()
    outcome = scheme.transform(setup["pk"], enc["ct"],
                               prov_revoked["keys"]["static"],
                               prov_revoked["keys"]["private"], ku, metrics)
    assert outcome is None
    assert metrics.status == "revoked-or-invalid-path"

    # active user still decrypts
    tr = adapter.transform(scheme, setup["pk"], enc["ct"], prov_active["keys"],
                           ku)
    assert tr["status"] == "ok"
    fd = adapter.final_dec(scheme, setup["pk"], tr["transformed"],
                           prov_active["keys"])
    assert fd["msg"] == workload.message_bytes


def test_fresh_ciphertext_per_repetition(group):
    """No cross-repetition caching: fresh schemes yield distinct ciphertexts."""
    adapter = create_adapter("FXABE-Full", group)
    workload = _workload()
    scheme1, setup1, _, _ = _prepared(adapter, workload, seed=1)
    enc1 = _encrypt(adapter, scheme1, setup1, workload, seed=1)
    scheme2, setup2, _, _ = _prepared(adapter, workload, seed=2)
    enc2 = _encrypt(adapter, scheme2, setup2, workload, seed=2)
    assert enc1["ct"]["C"] != enc2["ct"]["C"]
    assert enc1["ct"]["nonce"] != enc2["ct"]["nonce"]


def test_tampered_dem_fails(group):
    """KEM-DEM integrity: a flipped C_sym byte must not authenticate."""
    adapter = create_adapter("FXABE-Full", group)
    workload = _workload()
    scheme, setup, prov, ku = _prepared(adapter, workload)
    enc = _encrypt(adapter, scheme, setup, workload)
    tampered = dict(enc["ct"])
    tampered["C_sym"] = bytes([tampered["C_sym"][0] ^ 0x01]) + \
        tampered["C_sym"][1:]
    tr = adapter.transform(scheme, setup["pk"], tampered, prov["keys"], ku)
    assert tr["status"] == "ok"
    fd = adapter.final_dec(scheme, setup["pk"], tr["transformed"],
                           prov["keys"])
    assert fd["msg"] is None


def test_pair_count_is_real(group):
    """Pairing count matches the algebra: 2 revocation + 2 per satisfied row."""
    for scheme_name in ("FXABE-Base", "FXABE-Full"):
        adapter = create_adapter(scheme_name, group)
        workload = _workload(l=8, user_attrs=8)  # satisfied = 4
        scheme, setup, prov, ku = _prepared(adapter, workload)
        enc = _encrypt(adapter, scheme, setup, workload)
        tr = adapter.transform(scheme, setup["pk"], enc["ct"], prov["keys"],
                               ku)
        assert tr["status"] == "ok"
        assert tr["pair_count"] == 2 + 2 * workload.satisfied_rows
