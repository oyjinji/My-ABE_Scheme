"""Experiments 5-6: payload width, filter bytes and PStore distributions."""

import random

from experiments.index_v1.filters.fxabf_fuse import FXABFFuse
from experiments.index_v1.generators import generate_posting_lists, token_entries
from .common import ExperimentRun, configure, parser


def combination_count(config):
    storage = config["experiments"]["storage"]
    pstore = config["experiments"]["pstore"]
    return (len(storage["u"]) * len(storage["delta"]) * int(storage["trials"]) +
            len(pstore["u"]) * len(pstore["distributions"]) * int(pstore["trials"]))


def run(run_context):
    _run_filter_storage(run_context)
    if not run_context.interrupted:
        _run_pstore(run_context)


def _run_filter_storage(run_context):
    grid = run_context.config["experiments"]["storage"]
    completed = run_context.completed_keys("exp05_storage")
    for u in grid["u"]:
        for delta in grid["delta"]:
            for trial in range(int(grid["trials"])):
                key = "u={0}|delta={1}|trial={2}".format(u, delta, trial)
                if key in completed:
                    continue
                seed = run_context.seed("storage", u, delta, trial)
                try:
                    entries = token_entries(int(u), seed)
                    config = dict(run_context.config["filter"])
                    config["delta"] = int(delta)
                    backend = FXABFFuse()
                    index = backend.build(entries, config, random.Random(seed))
                    size = backend.serialized_size(index)
                    core = index["core"]
                    row = {
                        "u": int(u), "delta": int(delta), "trial": trial, "seed": seed,
                        "b_j": index["b_j"], "payload_bits": core["payload_bits"],
                        "m": core["m"], "bytes_per_token": size["filter_bytes"] / float(u),
                    }
                    row.update(size)
                    run_context.record("exp05_storage", key, row)
                except Exception as exc:
                    run_context.record_failure("exp05_storage", key, {"u": u, "delta": delta}, seed, exc)
                if run_context.interrupted:
                    return


def _run_pstore(run_context):
    grid = run_context.config["experiments"]["pstore"]
    completed = run_context.completed_keys("exp06_pstore")
    for u in grid["u"]:
        for distribution in grid["distributions"]:
            for trial in range(int(grid["trials"])):
                key = "u={0}|dist={1}|trial={2}".format(u, distribution, trial)
                if key in completed:
                    continue
                seed = run_context.seed("pstore", u, distribution, trial)
                try:
                    postings = generate_posting_lists(int(u), distribution, seed)
                    entries = token_entries(int(u), seed, postings)
                    backend = FXABFFuse()
                    index = backend.build(entries, run_context.config["filter"], random.Random(seed))
                    size = backend.serialized_size(index)
                    ell = sum(len(rows) for rows in postings)
                    nonce_bytes = 12 * int(u)
                    tag_bytes = 16 * int(u)
                    row_id_payload_bytes = sum(4 + 4 * len(rows) for rows in postings)
                    ciphertext_bytes = size["pstore_bytes"] - nonce_bytes
                    run_context.record("exp06_pstore", key, {
                        "u": int(u), "ell": ell, "distribution": distribution,
                        "trial": trial, "seed": seed,
                        "row_id_payload_bytes": row_id_payload_bytes,
                        "nonce_bytes": nonce_bytes, "tag_bytes": tag_bytes,
                        "ciphertext_bytes": ciphertext_bytes, "padding_bytes": 0,
                        "pstore_bytes": size["pstore_bytes"],
                        "pstore_bytes_per_token": size["pstore_bytes"] / float(u),
                        "pstore_bytes_per_policy_row": size["pstore_bytes"] / float(ell),
                    })
                except Exception as exc:
                    run_context.record_failure("exp06_pstore", key, {"u": u, "distribution": distribution}, seed, exc)
                if run_context.interrupted:
                    return


def main():
    args = parser(__doc__).parse_args()
    config = configure(args)
    if args.dry_run:
        print("exp05+06 combinations: {0}".format(combination_count(config)))
        return
    context = ExperimentRun(config, args.run_id, args.resume)
    run(context)
    context.summarize()
    print(context.run_dir)


if __name__ == "__main__":
    main()
