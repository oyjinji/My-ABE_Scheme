"""Deterministic shared token, posting and query workloads."""

import hashlib
import random

from .common import workload_id


def token_bytes(seed, label):
    return hashlib.sha256(
        ("FXEXP-token|%s|%s" % (seed, label)).encode("utf-8")
    ).digest()


def f1_workload(u, kind, seed):
    rng = random.Random(seed)
    tokens = [token_bytes(seed, i) for i in range(u)]
    if kind == "F1-A":
        entries = {token: [i + 1] for i, token in enumerate(tokens)}
        ell = u
    elif kind == "F1-B":
        assignments = list(range(u))
        # Three additional rows per token on average, with a bounded,
        # reproducible mild Zipf-like skew.
        weights = [1.0 / ((i + 8) ** 0.35) for i in range(u)]
        assignments.extend(rng.choices(range(u), weights=weights, k=3 * u))
        rng.shuffle(assignments)
        entries = {token: [] for token in tokens}
        for row_id, token_id in enumerate(assignments, 1):
            entries[tokens[token_id]].append(row_id)
        entries = {token: rows for token, rows in entries.items() if rows}
        ell = 4 * u
    else:
        raise ValueError("unknown F1 workload")
    return {
        "entries": entries, "u": u, "ell": ell,
        "workload_id": workload_id("F1", seed, u=u, workload=kind),
    }


def filter_query_workload(u, member_count, nonmember_count, seed):
    rng = random.Random(seed)
    entries = {token_bytes(seed, "m-%d" % i): [i + 1] for i in range(u)}
    members = [rng.choice(tuple(entries)) for _ in range(member_count)]
    nonmembers = [token_bytes(seed, "x-%d" % i) for i in range(nonmember_count)]
    return {
        "entries": entries, "members": members, "nonmembers": nonmembers,
        "workload_id": workload_id(
            "F3", seed, u=u, members=member_count, nonmembers=nonmember_count
        ),
    }


def transform_policy(ell):
    return {
        "matrix": [[1] for _ in range(ell)],
        "rho": ["policy-%05d" % i for i in range(ell)],
    }


def transform_attributes(ell, n, r):
    if r > min(ell, n):
        raise ValueError("r must not exceed ell or N")
    return (["policy-%05d" % i for i in range(r)] +
            ["nonmember-%05d" % i for i in range(n - r)])
