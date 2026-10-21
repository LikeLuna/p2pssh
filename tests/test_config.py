import json
import pytest
from p2pssh.config import Config, ConfigError, load_config, save_config


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("P2PSSH_HOME", str(tmp_path))
    return tmp_path


def test_missing_file_gives_defaults(home):
    c = load_config()
    assert c.port == 0 and c.allow_self is False
    assert c.key_dir == str(home) and c.trust_path.endswith("known_peers.json")
    c.validate()


def test_save_then_load_roundtrip():
    save_config(Config(name="asha", port=5000, allow_self=True))
    c = load_config()
    assert (c.name, c.port, c.allow_self) == ("asha", 5000, True)


def test_corrupt_file_is_backed_up_and_defaults_used(home):
    p = home / "config.json"
    p.write_text("{not json")
    assert load_config().port == 0
    assert (home / "config.json.bad").read_text() == "{not json"


def test_non_object_json_handled(home):
    (home / "config.json").write_text("[1,2]")
    assert load_config().port == 0


def test_unknown_keys_ignored(home):
    (home / "config.json").write_text(json.dumps({"name": "ben", "evil": 1}))
    assert load_config().name == "ben"


@pytest.mark.parametrize("kw", [
    {"name": "a b"}, {"name": "x" * 33}, {"port": -1}, {"port": 70000},
    {"port": "80"}, {"port": True}, {"allow_self": "yes"},
])
def test_invalid_values_rejected_on_save(kw):
    with pytest.raises(ConfigError):
        save_config(Config(**kw))


def test_invalid_value_in_file_rejected(home):
    (home / "config.json").write_text(json.dumps({"port": 99999}))
    with pytest.raises(ConfigError):
        load_config()


def test_no_temp_files_left_behind(home):
    save_config(Config(name="asha"))
    assert [p.name for p in home.iterdir()] == ["config.json"]