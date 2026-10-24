import base64
import json

import pytest

from p2pssh.identity import TrustStore, fingerprint

KEY1 = bytes(range(32))
KEY2 = bytes(range(1, 33))


@pytest.fixture
def store(tmp_path):
    return TrustStore(tmp_path / "known_peers.json")


def test_finds_name_by_fingerprint(store):
    store.add("ben", KEY1)
    store.add("dev", KEY2)
    assert store.find_by_fingerprint(fingerprint(KEY1)) == "ben"
    assert store.find_by_fingerprint(fingerprint(KEY2)) == "dev"


def test_unknown_fingerprint_returns_none(store):
    store.add("ben", KEY1)
    assert store.find_by_fingerprint(fingerprint(KEY2)) is None


def test_empty_store_returns_none(store):
    assert store.find_by_fingerprint(fingerprint(KEY1)) is None


def test_lookup_never_writes_the_file(store):
    store.find_by_fingerprint(fingerprint(KEY1))
    assert not store.path.exists()


def test_removed_peer_is_not_found(store):
    store.add("ben", KEY1)
    store.remove("ben")
    assert store.find_by_fingerprint(fingerprint(KEY1)) is None


@pytest.mark.parametrize("bad", ["", None, 123, b"SHA256:abc"])
def test_invalid_fingerprint_argument_raises(store, bad):
    with pytest.raises(ValueError):
        store.find_by_fingerprint(bad)


def test_lookup_is_exact_not_prefix(store):
    store.add("ben", KEY1)
    assert store.find_by_fingerprint(fingerprint(KEY1)[:-1]) is None
    assert store.find_by_fingerprint(fingerprint(KEY1) + "x") is None


def test_same_key_under_two_names_returns_first_alphabetically(store):
    store.add("zed", KEY1)
    store.add("amy", KEY1)
    assert store.find_by_fingerprint(fingerprint(KEY1)) == "amy"


def test_edited_fingerprint_field_cannot_fool_lookup(store):
    store.add("ben", KEY1)
    data = json.loads(store.path.read_text(encoding="utf-8"))
    data["ben"]["fingerprint"] = fingerprint(KEY2)          # tampered label
    store.path.write_text(json.dumps(data), encoding="utf-8")
    assert store.find_by_fingerprint(fingerprint(KEY2)) is None
    assert store.find_by_fingerprint(fingerprint(KEY1)) == "ben"


def test_malformed_entries_are_skipped(store):
    store.path.write_text(json.dumps({
        "broken1": {"oops": 1},
        "broken2": {"pubkey_b64": "!!!not base64!!!"},
        "broken3": {"pubkey_b64": base64.b64encode(b"short").decode()},
        "broken4": "not a dict",
    }), encoding="utf-8")
    assert store.find_by_fingerprint(fingerprint(KEY1)) is None
    store.add("ben", KEY1)
    assert store.find_by_fingerprint(fingerprint(KEY1)) == "ben"