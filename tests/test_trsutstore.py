import json
import os
import threading

import pytest

from p2pssh.identity import TrustError, TrustResult, TrustStore, fingerprint


@pytest.fixture
def store(tmp_path):
    return TrustStore(tmp_path / "known_peers.json")


KEY1 = bytes(range(32))
KEY2 = bytes(range(1, 33))


def test_unknown_peer_is_new(store):                          # A1-N5
    assert store.check("ben", KEY1) == TrustResult.NEW


def test_add_then_check_same_key_is_trusted(store):           # A1-N6
    store.add("ben", KEY1)
    assert store.check("ben", KEY1) == TrustResult.TRUSTED


def test_different_key_is_changed(store):                     # A1-N7
    store.add("ben", KEY1)
    assert store.check("ben", KEY2) == TrustResult.CHANGED


def test_remove_then_check_is_new(store):                     # A1-N8
    store.add("ben", KEY1)
    store.remove("ben")
    assert store.check("ben", KEY1) == TrustResult.NEW


def test_trust_survives_restart(tmp_path):
    path = tmp_path / "known_peers.json"
    TrustStore(path).add("ben", KEY1)
    assert TrustStore(path).check("ben", KEY1) == TrustResult.TRUSTED


def test_file_contents(store):
    store.add("ben", KEY1)
    entry = json.loads(store.path.read_text(encoding="utf-8"))["ben"]
    assert entry["fingerprint"] == fingerprint(KEY1)
    assert set(entry) == {"fingerprint", "pubkey_b64", "first_seen"}


def test_adding_same_key_twice_keeps_first_seen(store):
    store.add("ben", KEY1)
    first = store.list_peers()["ben"]["first_seen"]
    store.add("ben", KEY1)
    assert store.list_peers()["ben"]["first_seen"] == first


def test_add_different_key_for_known_name_is_refused(store):
    store.add("ben", KEY1)
    with pytest.raises(TrustError):
        store.add("ben", KEY2)
    assert store.check("ben", KEY1) == TrustResult.TRUSTED   # old key untouched


def test_accepting_a_changed_key_requires_remove_first(store):
    store.add("ben", KEY1)
    store.remove("ben")
    store.add("ben", KEY2)
    assert store.check("ben", KEY2) == TrustResult.TRUSTED


def test_remove_unknown_peer_is_harmless(store):
    store.remove("nobody")


def test_list_peers(store):
    store.add("ben", KEY1)
    store.add("dev", KEY2)
    peers = store.list_peers()
    assert set(peers) == {"ben", "dev"}
    assert peers["ben"]["fingerprint"] == fingerprint(KEY1)


# ---------- boundary cases ----------

def test_invalid_json_is_backed_up_and_treated_as_empty(tmp_path):    # A1-B8
    path = tmp_path / "known_peers.json"
    path.write_text("{ this is not json", encoding="utf-8")
    store = TrustStore(path)
    assert store.check("ben", KEY1) == TrustResult.NEW
    assert (tmp_path / "known_peers.json.corrupt").exists()


def test_empty_file_does_not_crash(tmp_path):                         # A1-B8
    path = tmp_path / "known_peers.json"
    path.write_text("", encoding="utf-8")
    assert TrustStore(path).check("ben", KEY1) == TrustResult.NEW


def test_json_that_is_not_an_object_is_handled(tmp_path):
    path = tmp_path / "known_peers.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert TrustStore(path).check("ben", KEY1) == TrustResult.NEW


def test_malformed_entry_is_never_trusted(tmp_path):
    path = tmp_path / "known_peers.json"
    path.write_text(json.dumps({"ben": {"oops": 1}}), encoding="utf-8")
    assert TrustStore(path).check("ben", KEY1) == TrustResult.CHANGED


@pytest.mark.parametrize("size", [0, 31, 33])
def test_wrong_length_public_key_raises(store, size):
    with pytest.raises(ValueError):
        store.check("ben", b"\x01" * size)
    with pytest.raises(ValueError):
        store.add("ben", b"\x01" * size)


def test_unicode_peer_name(store):                                    # A1-B10
    store.add("बेन-🔑", KEY1)
    assert store.check("बेन-🔑", KEY1) == TrustResult.TRUSTED


def test_very_long_or_empty_name_is_rejected(store):                  # A1-B10
    with pytest.raises(ValueError):
        store.add("x" * 500, KEY1)
    with pytest.raises(ValueError):
        store.add("", KEY1)


def test_no_temp_files_left_behind(store):
    store.add("ben", KEY1)
    store.add("dev", KEY2)
    assert [p.name for p in store.path.parent.iterdir()] == ["known_peers.json"]


def test_concurrent_adds_in_one_process_lose_nothing(store):          # A1-B9 (threads)
    names = [f"peer{i}" for i in range(20)]
    threads = [
        threading.Thread(target=store.add, args=(n, os.urandom(32))) for n in names
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(store.list_peers()) == set(names)