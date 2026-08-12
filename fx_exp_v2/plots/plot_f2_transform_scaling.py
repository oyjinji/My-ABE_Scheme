from .common import load_summary, new_figure, plot_metric, save_both


def plot(run_dir, filters):
    data = load_summary(run_dir, "f2_transform_scaling")
    total = data[(data["metric"] == "transform_total_ms") &
                 (data["experiment"] == "F2-A")]
    core = data[(data["metric"] == "core_transform_ms") &
                (data["experiment"] == "F2-A")]
    fig, ax = new_figure()
    plot_metric(ax, total, "ell", filters)
    baseline = core.groupby("ell", as_index=False)["median"].median().sort_values("ell")
    ax.plot(baseline["ell"], baseline["median"], color="#444444", marker="x",
            linestyle=":", linewidth=1.5, label="Common core baseline")
    ax.set_title("Transform Time vs Policy Rows (N=32, r=8)")
    ax.set_xlabel("Policy rows (ell)")
    ax.set_ylabel("Median time (ms)")
    ax.legend()
    save_both(fig, run_dir, "supplemental/f2_transform_scaling")
