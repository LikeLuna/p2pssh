import pytest
from p2pssh.cli import main


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("P2PSSH_HOME", str(tmp_path))


KEY = "ab" * 32


def test_whoami_shows_fingerprint(capsys):
    assert main(["whoami"]) == 0
    assert "SHA256:" in capsys.readouterr().out


def test_trust_add_list_remove(capsys):
    assert main(["trust", "add", "ben", KEY]) == 0
    capsys.readouterr()
    main(["trust", "list"])
    assert "ben" in capsys.readouterr().out
    assert main(["trust", "remove", "ben"]) == 0
    capsys.readouterr()
    main(["trust", "list"])
    assert "no trusted peers" in capsys.readouterr().out


def test_trust_add_bad_input():
    assert main(["trust", "add", "ben", "zz"]) == 1
    assert main(["trust", "add", "ben", "abcd"]) == 1   # wrong length
    assert main(["trust", "add"]) == 1


def test_trust_changed_key_refused(capsys):
    main(["trust", "add", "ben", KEY])
    assert main(["trust", "add", "ben", "cd" * 32]) == 1
    assert "different key" in capsys.readouterr().out


def test_config_set_and_persist(capsys):
    assert main(["config", "set", "port", "5000"]) == 0
    main(["config", "show"])
    assert "5000" in capsys.readouterr().out


def test_config_bad_values():
    assert main(["config", "set", "port", "abc"]) == 1
    assert main(["config", "set", "port", "99999"]) == 1
    assert main(["config", "set", "allow_self", "maybe"]) == 1
    assert main(["config", "set", "nope", "1"]) == 1


def test_placeholders_return_2():
    assert main(["shell"]) == 2