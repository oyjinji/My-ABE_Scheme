import json

from experiments.index_v1.runners import common


def test_profiles_parse_and_full_grid_is_nonempty():
    for profile in ("smoke", "standard", "full"):
        config = common.load_config(profile)
        assert config["profile"] == profile
        assert config["experiments"]["transform"]["N"] == 32
        assert config["experiments"]["transform"]["r"] == 8


def test_result_append_and_resume(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "RESULTS", tmp_path)
    config = common.load_config("smoke")
    run = common.ExperimentRun(config, "resume-test")
    run.record("example", "key-1", {"value": 1})
    resumed = common.ExperimentRun(config, "resume-test", resume=True)
    assert resumed.completed_keys("example") == {"key-1"}
    manifest = json.loads((tmp_path / "resume-test" / "manifest.json").read_text())
    assert manifest["master_seed"] == config["master_seed"]
