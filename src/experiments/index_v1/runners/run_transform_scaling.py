"""Experiment 9: fixed N/r Core Transform while policy rows grow."""

import random
from time import perf_counter_ns

from charm.toolbox.pairinggroup import PairingGroup, pair

from core.fxdacp import FXDACP
from experiments.index_v1.filters import create_backends
from experiments.index_v1.generators import fixed_match_or_policy, user_attributes
from .common import ExperimentRun, configure, parser


def combination_count(config):
    grid = config["experiments"]["transform"]
    return len(grid["ell"]) * len(grid["backends"]) * int(grid["trials"])


def run(run_context):
    grid = run_context.config["experiments"]["transform"]
    completed = run_context.completed_keys("exp09_transform")
    group = PairingGroup(run_context.config.get("pairing_group", "MNT224"))
    for ell in grid["ell"]:
        for trial in range(int(grid["trials"])):
            workload_seed = run_context.seed("transform-workload", ell, trial)
            scheme = FXDACP(group, rng=random.Random(workload_seed))
            pk, msk = scheme.setup()
            policy, matching = fixed_match_or_policy(int(ell), int(grid["r"]))
            attrs = user_attributes(int(grid["N"]), matching)
            tk, rk = scheme.keygen(pk, msk, attrs, epoch="transform")
            # Ciphertext generation is intentionally outside all Transform timings.
            ciphertext = scheme.encrypt(pk, msk, b"transform-scaling", policy, epoch="transform")
            formal = scheme.transform(pk, ciphertext, tk)
            if scheme.final_dec(pk, formal, rk) != b"transform-scaling":
                raise AssertionError("formal FXDACP preflight failed")
            entries = {}
            for row_id, attr in enumerate(policy["rho"], 1):
                token = scheme.oprf.direct_token(attr, "transform", "1", msk["kappa"])
                entries.setdefault(scheme.oprf.token_bytes(token), []).append(row_id)
            key_by_token = {item["token_bytes"]: item["K_x"] for item in tk["items"]}
            for backend in create_backends(grid["backends"]):
                key = "ell={0}|trial={1}|backend={2}".format(ell, trial, backend.name)
                if key in completed:
                    continue
                seed = run_context.seed("transform-backend", ell, trial, backend.name)
                try:
                    index = backend.build(entries, run_context.config["filter"], random.Random(seed))
                    # Warm-up one known query before timing.
                    backend.query(index, next(iter(entries)))
                    core_started = perf_counter_ns()
                    query_started = perf_counter_ns()
                    row_keys = {}
                    pstore_ns = 0
                    for token, key_component in key_by_token.items():
                        result = backend.query(index, token)
                        pstore_ns += result.metrics.get("pstore_ns", 0)
                        if result.hit:
                            for row_id in result.posting_list:
                                row_keys[row_id] = key_component
                    filter_query_ns = perf_counter_ns() - query_started
                    pairing_started = perf_counter_ns()
                    pair(ciphertext["C"], tk["K0"])
                    for row_id in sorted(row_keys):
                        row = ciphertext["rows"][row_id - 1]
                        pair(row["C1"], tk["K1"]) * pair(row_keys[row_id], row["C2"])
                    pairing_ns = perf_counter_ns() - pairing_started
                    core_ns = perf_counter_ns() - core_started
                    r_actual = len(row_keys)
                    if r_actual != int(grid["r"]):
                        raise AssertionError("fixed-r workload produced r={0}".format(r_actual))
                    run_context.record("exp09_transform", key, {
                        "backend": backend.name, "ell": int(ell), "N": int(grid["N"]),
                        "r": r_actual, "trial": trial, "seed": seed,
                        "filter_query_ns": filter_query_ns,
                        "pstore_processing_ns": pstore_ns,
                        "pairing_ns": pairing_ns,
                        "other_ns": max(0, core_ns - filter_query_ns - pairing_ns),
                        "core_transform_ns": core_ns,
                        "e2e_transform_ns": core_ns,
                        "pairing_count": 1 + 2 * r_actual,
                    })
                except Exception as exc:
                    run_context.record_failure("exp09_transform", key, {
                        "backend": backend.name, "ell": ell,
                    }, seed, exc)
                if run_context.interrupted:
                    return


def main():
    args = parser(__doc__).parse_args()
    config = configure(args)
    if args.dry_run:
        print("exp09 combinations: {0}".format(combination_count(config)))
        return
    context = ExperimentRun(config, args.run_id, args.resume)
    run(context)
    context.summarize()
    print(context.run_dir)


if __name__ == "__main__":
    main()
