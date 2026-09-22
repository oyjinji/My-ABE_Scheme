"""Deterministic real-crypto workloads shared by all six experiments."""

import random
from time import perf_counter_ns

from Code.fxabe_rev import FXABERev
from Code.fxabe_rev.filters import create_index

from .common import derive_seed


def new_scheme(group, capacity, seed, filter_options=None):
    scheme = FXABERev(
        group, user_capacity=int(capacity), scheme_seed=int(seed),
        filter_options=filter_options,
    )
    pp, msk = scheme.setup()
    return scheme, pp, msk


def placement(master_seed, experiment, n, r_v, placement_seed, excluded=()):
    candidates = [value for value in range(int(n)) if value not in set(excluded)]
    rng = random.Random(derive_seed(
        int(master_seed), experiment, n, r_v, placement_seed
    ))
    return tuple(sorted(rng.sample(candidates, int(r_v))))


def or_policy(ell):
    return "(" + " or ".join("P%04d" % index for index in range(int(ell))) + ")"


def transform_attributes(N, r):
    return (["P%04d" % index for index in range(int(r))] +
            ["U%04d" % index for index in range(int(N) - int(r))])


def build_policy_privacy_material(scheme, pp, msk, ell, unique_attributes,
                                  privacy_epoch, seed):
    """Refresh policy tokens, then build real FX-ABF and encrypted PStore."""
    ell = int(ell)
    unique_attributes = int(unique_attributes)
    if not 1 <= unique_attributes <= ell:
        raise ValueError("policy_unique_attributes must be in [1, ell]")
    started = perf_counter_ns()
    token_map = {}
    token_cache = {}
    for row in range(ell):
        attribute = "P%04d" % (row % unique_attributes)
        if attribute in token_cache:
            token_bytes = token_cache[attribute]
            token_map[token_bytes].append(row + 1)
            continue
        token = scheme.oprf.direct_token(
            attribute, privacy_epoch, pp["version"], msk["kappa"]
        )
        token_bytes = scheme.oprf.token_bytes(token)
        token_cache[attribute] = token_bytes
        token_map[token_bytes] = [row + 1]
    token_map = {token: tuple(rows) for token, rows in token_map.items()}
    token_refresh_ns = perf_counter_ns() - started

    context = ("Rev_Exp-policy-context|%s|%d|%d" %
               (privacy_epoch, ell, unique_attributes)).encode("utf-8")
    index = create_index("FX-ABF", **scheme.filter_options)
    build_started = perf_counter_ns()
    index.build(token_map, context, random.Random(int(seed)))
    build_wall_ns = perf_counter_ns() - build_started
    stats = index.stats()
    pstore_ns = int(stats["pstore_build_ns"])
    fx_rebuild_ns = build_wall_ns - pstore_ns
    return {
        "token_refresh_ns": token_refresh_ns,
        "fx_rebuild_ns": fx_rebuild_ns,
        "pstore_rebuild_ns": pstore_ns,
        "policy_refresh_total_ns": token_refresh_ns + build_wall_ns,
        "fx_build_attempts": int(stats["attempt_count"]),
        "fx_resize_count": int(stats["resize_count"]),
        "index": index,
    }


def initialize_lightweight_users(scheme, n, attributes):
    """Create valid KeyGen-held state outside timing without privacy output.

    The coupled ablation times only PrivacyKeyUpt.  Each user gets independently
    generated eta/z scalars and a real tree leaf; omitting the unused old TK_priv
    avoids performing an extra O(nS) refresh before every timed sample.
    """
    tree = scheme.state["tree"]
    attrs = list(attributes)
    for index in range(int(n)):
        identity = "user-%d" % index
        tree.register(identity)
        scheme.state["user_state"][identity] = {
            "attributes": attrs,
            "eta": scheme.scalar_source.scalar(nonzero=True),
            "z": scheme.scalar_source.scalar(nonzero=True),
            "version": "1",
        }


def bulk_privacy_update(scheme, pp, msk, active_indices, privacy_epoch):
    started = perf_counter_ns()
    count = 0
    for index in active_indices:
        value = scheme.privacy_key_upt(
            pp, msk, "user-%d" % int(index), privacy_epoch
        )
        if not value["items"]:
            raise AssertionError("PrivacyKeyUpt returned no components")
        count += 1
    return perf_counter_ns() - started, count
