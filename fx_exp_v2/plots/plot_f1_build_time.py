from .common import load_summary, new_figure, plot_metric, save_both


def plot(run_dir, filters):
    data = load_summary(run_dir, "f1_build_space")
    data = data[(data["metric"] == "build_total_ms") & (data["workload"] == "F1-A")]
    fig, ax = new_figure()
    plot_metric(ax, data, "u", filters)
    ax.set_title("Integrated Anonymous Index Build Time vs Number of Tokens")
    ax.set_xlabel("Number of distinct tokens (u)")
    ax.set_ylabel("Median build time (ms)")
    ax.set_xscale("log", base=2)
    ax.legend()
    save_both(fig, run_dir, "f1_build_time")
