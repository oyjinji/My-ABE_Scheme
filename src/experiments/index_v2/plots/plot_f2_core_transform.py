from .common import load_summary, new_figure, plot_metric, save_both


def plot(run_dir, filters):
    data = load_summary(run_dir, "f2_transform_scaling")
    data = data[(data["metric"] == "core_transform_ms") &
                (data["experiment"] == "F2-B")]
    fig, ax = new_figure()
    plot_metric(ax, data, "r", filters)
    ax.set_title("Core Transform Time vs Matched Rows")
    ax.set_xlabel("Matched, deduplicated rows (r)")
    ax.set_ylabel("Median core Transform time (ms)")
    values = sorted(data["r"].unique())
    top = ax.secondary_xaxis("top")
    top.set_xticks(values)
    top.set_xticklabels([str(2 + 2 * int(r)) for r in values])
    top.set_xlabel("Theoretical and validated pairing calls (2+2r)")
    ax.legend()
    save_both(fig, run_dir, "f2_core_transform")
