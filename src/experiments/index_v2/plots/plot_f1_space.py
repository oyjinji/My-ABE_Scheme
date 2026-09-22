from .common import load_summary, new_figure, plot_metric, save_both


def plot(run_dir, filters):
    data = load_summary(run_dir, "f1_build_space")
    data = data[(data["metric"] == "bytes_per_token") & (data["workload"] == "F1-A")]
    fig, ax = new_figure()
    plot_metric(ax, data, "u", filters)
    ax.set_title("Integrated Index Size per Token")
    ax.set_xlabel("Number of distinct tokens (u)")
    ax.set_ylabel("Integrated bytes per token")
    ax.set_xscale("log", base=2)
    ax.legend(title="Integrated index (optional locator + PStore)")
    save_both(fig, run_dir, "f1_index_space")
