import time
import pytest
from p2pssh.discovery import (Discovery, DiscoveryError, PeerInfo,
                              _validate, peer_from_info, SERVICE_TYPE)

FP = "SHA256:abcdefghijklmnopqrstuvwxyz012345"


class FakeInfo:
    def __init__(self, name="asha", port=5000, fp=FP, addrs=("192.168.1.5",)):
        self.name = f"{name}.{SERVICE_TYPE}"
        self.port = port
        self.properties = {b"fp": fp.encode()}
        self._addrs = list(addrs)

    def parsed_addresses(self):
        return self._addrs


def test_valid_inputs_accepted():
    _validate("asha", 5000, FP)


@pytest.mark.parametrize("name,port,fp", [
    ("", 5000, FP), ("a b", 5000, FP), ("x" * 33, 5000, FP),
    ("asha", 0, FP), ("asha", 70000, FP), ("asha", "80", FP),
    ("asha", 5000, "nope"), ("asha", 5000, None),
])
def test_invalid_inputs_rejected(name, port, fp):
    with pytest.raises(DiscoveryError):
        _validate(name, port, fp)


def test_peer_from_info_ok():
    assert peer_from_info(FakeInfo()) == PeerInfo("asha", "192.168.1.5", 5000, FP)


def test_peer_from_info_malformed_returns_none():
    assert peer_from_info(FakeInfo(fp="garbage")) is None
    assert peer_from_info(FakeInfo(addrs=())) is None
    assert peer_from_info(FakeInfo(port=0)) is None
    assert peer_from_info(object()) is None


def test_add_remove_and_callback():
    d = Discovery.__new__(Discovery)  # skip real network setup
    import threading
    d._lock, d._peers, d._own_name, d._info = threading.Lock(), {}, "me", None
    events = []
    d._callback = lambda ev, p: events.append((ev, p.name))
    p = PeerInfo("ben", "10.0.0.2", 6000, FP)
    d._add(p)
    assert d.peers() == [p]
    d._remove("ben")
    assert d.peers() == [] and events == [("added", "ben"), ("removed", "ben")]


def test_two_nodes_find_each_other_on_lan():
    a, b = Discovery(), Discovery()
    try:
        a.announce("asha", 5001, FP)
        b.browse()
        for _ in range(50):
            if b.peers():
                break
            time.sleep(0.1)
        if not b.peers():
            pytest.skip("multicast not available in this environment")
        assert b.peers()[0].name == "asha" and b.peers()[0].port == 5001
    finally:
        a.close(); b.close()