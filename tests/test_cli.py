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

def test_shell_off_by_default(capsys):
    assert main(["shell", "ben"]) == 1
    assert "OFF" in capsys.readouterr().out

def test_shell_needs_trusted_peer(capsys):
    main(["config", "set", "allow_shell", "true"])
    assert main(["shell", "ben"]) == 1
    assert "not trusted" in capsys.readouterr().out

def test_keygen_never_overwrites(capsys):
    main(["keygen"]); main(["keygen"])
    assert "already exists" in capsys.readouterr().out


# ---------------------------------------------------------------- listen / connect (real loopback TCP)
import asyncio

from p2pssh import cli
from p2pssh.config import load_config
from p2pssh.identity import TrustStore, fingerprint, load_or_create_identity
from p2pssh.transport import Node


async def _server(tmp_path):
    """A responder with its OWN identity and trust store, on a free loopback port."""
    sdir = tmp_path / "server"
    ident = load_or_create_identity(sdir)
    trust = TrustStore(sdir / "known_peers.json")
    node = Node()
    await node.listen("127.0.0.1", 0, cli.make_on_conn(ident, trust, load_config()))
    return node, ident, trust


def _answer(monkeypatch, value):
    monkeypatch.setattr(cli, "confirm_fingerprint", lambda name, fp, **kw: value)


async def _connect(node):
    return await asyncio.to_thread(main, ["connect", f"127.0.0.1:{node.port}"])


async def test_connect_new_peer_accepted_and_remembered(tmp_path, monkeypatch, capsys):
    _answer(monkeypatch, True)
    node, ident, _ = await _server(tmp_path)
    try:
        assert await _connect(node) == 0
        assert "secure channel established (initiator)" in capsys.readouterr().out
        saved = TrustStore(load_config().trust_path).list_peers()
        assert saved[f"127.0.0.1:{node.port}"]["fingerprint"] == fingerprint(ident.public_bytes())
    finally:
        await node.close()


async def test_connect_new_peer_rejected(tmp_path, monkeypatch, capsys):
    _answer(monkeypatch, False)
    node, _, _ = await _server(tmp_path)
    try:
        assert await _connect(node) == 1
        assert "handshake failed" in capsys.readouterr().out
        assert TrustStore(load_config().trust_path).list_peers() == {}
    finally:
        await node.close()


async def test_second_connect_needs_no_prompt(tmp_path, monkeypatch):
    _answer(monkeypatch, True)
    node, _, _ = await _server(tmp_path)
    try:
        assert await _connect(node) == 0

        def must_not_ask(*a, **k):
            raise AssertionError("user was asked about an already trusted peer")
        monkeypatch.setattr(cli, "confirm_fingerprint", must_not_ask)
        assert await _connect(node) == 0
    finally:
        await node.close()


async def test_connect_key_changed_is_refused(tmp_path, monkeypatch, capsys):
    _answer(monkeypatch, True)                       # even a 'yes' must not help
    node, _, _ = await _server(tmp_path)
    try:
        other = load_or_create_identity(tmp_path / "other").public_bytes()
        TrustStore(load_config().trust_path).add(f"127.0.0.1:{node.port}", other)
        assert await _connect(node) == 1
        out = capsys.readouterr().out
        assert "CHANGED" in out and "trust remove" in out
    finally:
        await node.close()


def test_connect_needs_target(capsys):
    assert main(["connect"]) == 1
    assert "usage" in capsys.readouterr().out


def test_connect_bad_address_and_closed_port(capsys):
    assert main(["connect", "nonsense:99999"]) == 1
    assert main(["connect", "127.0.0.1:1"]) == 1           # nothing listens there
    assert "error" in capsys.readouterr().out


def test_send_missing_file_checked_before_connecting(capsys):
    assert main(["send", "127.0.0.1:5000", "no_such_file.txt"]) == 1
    assert "file not found" in capsys.readouterr().out