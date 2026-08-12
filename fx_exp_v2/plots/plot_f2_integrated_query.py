"""F2-A integrated anonymous-index query phase, excluding ABE pairing."""

from .common import load_summary, new_figure, plot_metric, save_both


def plot(run_dir, filters):
    data = load_summary(run_dir, "f2_transform_scaling")
    data = data[
        (data["metric"] == "integrated_index_query_ms") &
        (data["experiment"] == "F2-A")
    ]
    fig, ax = new_figure()
    plot_metric(ax, data, "ell", filters)
    ax.set_title("Integrated Index Query Time vs Policy Rows")
    ax.set_xlabel("Policy rows (ell), N=32 and r=8")
    ax.set_ylabel("Median complete index-query batch time (ms)")
    ax.legend()
    save_both(fig, run_dir, "f2_integrated_index_query")
