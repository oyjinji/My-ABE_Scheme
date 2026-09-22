"""Run all eleven FX-ABF experiments under one resumable run directory."""

from experiments.index_v1.plots.plot_all import plot_run
from . import (
    run_filter_suite, run_fxabf_build, run_query_breakdown,
    run_sensitivity, run_storage_suite, run_transform_scaling,
)
from .common import ExperimentRun, configure, parser


RUNNERS = [
    run_fxabf_build, run_query_breakdown, run_storage_suite,
    run_filter_suite, run_sensitivity, run_transform_scaling,
]


def main():
    args = parser(__doc__).parse_args()
    config = configure(args)
    if args.dry_run:
        counts = [(module.__name__.rsplit(".", 1)[-1], module.combination_count(config))
                  for module in RUNNERS]
        for name, count in counts:
            print("{0}: {1}".format(name, count))
        print("total combinations: {0}".format(sum(count for _, count in counts)))
        return
    context = ExperimentRun(config, args.run_id, args.resume)
    for module in RUNNERS:
        module.run(context)
        context.summarize()
        if context.interrupted:
            print("interrupted; resume with --run-id {0} --resume".format(context.run_id))
            return
    plot_run(context.run_dir)
    print(context.run_dir)


if __name__ == "__main__":
    main()
