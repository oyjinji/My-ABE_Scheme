import json

from experiments.index_v1.plots.plot_all import plot_run


def test_plotter_writes_png_pdf_and_csv(tmp_path):
    for child in ("raw", "plots", "plot_data"):
        (tmp_path / child).mkdir()
    rows = [
        {"status": "ok", "u": 16, "c_fx": 1.3, "first_attempt_success": 1,
         "build_ns": 100, "retries": 0, "expansions": 0, "final_m_per_u": 1.3},
        {"status": "ok", "u": 32, "c_fx": 1.3, "first_attempt_success": 1,
         "build_ns": 200, "retries": 1, "expansions": 0, "final_m_per_u": 1.3},
    ]
    with (tmp_path / "raw" / "exp01_03_build.jsonl").open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    plot_run(tmp_path)
    assert (tmp_path / "plots" / "exp01_first_success.png").exists()
    assert (tmp_path / "plots" / "exp01_first_success.pdf").exists()
    assert (tmp_path / "plot_data" / "exp01_first_success.csv").exists()
