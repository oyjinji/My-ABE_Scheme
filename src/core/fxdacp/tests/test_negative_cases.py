import copy
import random
import struct

from core.fxdacp.crypto_utils import aead_encrypt
from core.fxdacp.fxabf import FXABF, FXABFIndex


def _replace_plaintext(builder, index, token, ctx, plaintext):
    damaged = copy.deepcopy(index)
    value, _ = FXABF.query_value(damaged["fxabf"], token)
    identifier = value >> damaged["delta"]
    seed = damaged["fxabf"]["seed"]
    key = builder._posting_key(ctx, token, seed)
    aad = builder._posting_aad(ctx, damaged["u"], damaged["ell"], identifier)
    nonce = damaged["pstore"][identifier]["nonce"]
    damaged["pstore"][identifier] = aead_encrypt(key, plaintext, aad, nonce)
    return damaged


def test_duplicate_posting_rows_are_rejected():
    builder = FXABFIndex(rng=random.Random(20))
    index, _, _ = builder.build({b"member": [1, 2]}, b"ctx", 2)
    malformed = struct.pack(">III", 2, 1, 1)
    damaged = _replace_plaintext(builder, index, b"member", b"ctx", malformed)
    assert not builder.query(damaged, b"member", b"ctx").hit


def test_unsorted_posting_rows_are_rejected():
    builder = FXABFIndex(rng=random.Random(21))
    index, _, _ = builder.build({b"member": [1, 2]}, b"ctx", 2)
    malformed = struct.pack(">III", 2, 2, 1)
    damaged = _replace_plaintext(builder, index, b"member", b"ctx", malformed)
    assert not builder.query(damaged, b"member", b"ctx").hit


def test_out_of_range_posting_row_is_rejected():
    builder = FXABFIndex(rng=random.Random(22))
    index, _, _ = builder.build({b"member": [1]}, b"ctx", 1)
    malformed = struct.pack(">II", 1, 2)
    damaged = _replace_plaintext(builder, index, b"member", b"ctx", malformed)
    assert not builder.query(damaged, b"member", b"ctx").hit


def test_epoch_changes_token(group):
    from core.fxdacp.oprf import PairingOPRF
    from charm.toolbox.pairinggroup import ZR
    oprf = PairingOPRF(group)
    kappa = group.random(ZR)
    assert oprf.direct_token("A", "1", "1", kappa) != oprf.direct_token("A", "2", "1", kappa)
