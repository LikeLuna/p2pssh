"""Simultaneous-dial tie-break (p2pssh/tiebreak.py)."""

import itertools

import pytest

from p2pssh.tiebreak import (INITIATOR, RESPONDER, DialRegistry, initiator_fingerprint, wins)

A = "SHA256:AAAA"      # smaller
B = "SHA256:BBBB"      # larger


class Closer:
    def __init__(self):
        self.closed = False

    async def __call__(self):
        self.closed = True


# ---------- the pure rule ----------

def test_smaller_initiator_wins():
    assert wins(A, B, INITIATOR)          # A is smaller and dialed
    assert not wins(B, A, INITIATOR)      # B is larger and dialed


def test_both_sides_agree_on_the_same_connection():
    """c1 = dialed by A, c2 = dialed by B. A and B must keep the same one."""
    # A's view: c1 is INITIATOR, c2 is RESPONDER. B's view: c1 is RESPONDER, c2 is INITIATOR.
    a_keeps_c1 = wins(A, B, INITIATOR)
    b_keeps_c1 = wins(B, A, RESPONDER)
    a_keeps_c2 = wins(A, B, RESPONDER)
    b_keeps_c2 = wins(B, A, INITIATOR)
    assert a_keeps_c1 == b_keeps_c1
    assert a_keeps_c2 == b_keeps_c2
    assert a_keeps_c1 != a_keeps_c2       # exactly one of the two survives


@pytest.mark.parametrize("x,y", [("SHA256:a", "SHA256:b"), ("SHA256:Z", "SHA256:a"),
                                 ("SHA256:abc", "SHA256:abd"), ("SHA256:+x", "SHA256:/x")])
def test_rule_is_symmetric_for_any_pair(x, y):
    for init_is_x in (True, False):
        x_role = INITIATOR if init_is_x else RESPONDER
        y_role = RESPONDER if init_is_x else INITIATOR
        assert wins(x, y, x_role) == wins(y, x, y_role)     # same connection, same verdict


def test_self_connection_is_an_error():
    with pytest.raises(ValueError):
        wins(A, A, INITIATOR)


def test_unknown_role_is_an_error():
    with pytest.raises(ValueError):
        initiator_fingerprint(A, B, "sideways")


# ---------- the registry ----------

async def test_single_connection_is_kept():
    reg = DialRegistry(A)
    h = await reg.register(B, "chat", INITIATOR, Closer())
    assert h is not None and reg.live_count() == 1


async def test_same_direction_twice_is_not_a_duplicate():
    reg = DialRegistry(A)
    c1, c2 = Closer(), Closer()
    h1 = await reg.register(B, "file", INITIATOR, c1)
    h2 = await reg.register(B, "file", INITIATOR, c2)
    assert h1 and h2 and not c1.closed and not c2.closed


async def test_different_services_do_not_conflict():
    reg = DialRegistry(B)                  # B is the larger fingerprint
    c1, c2 = Closer(), Closer()
    await reg.register(A, "file", RESPONDER, c1)
    h = await reg.register(A, "shell", INITIATOR, c2)
    assert h is not None and not c1.closed and not c2.closed


async def test_different_peers_do_not_conflict():
    reg = DialRegistry(B)
    await reg.register("SHA256:C", "chat", RESPONDER, Closer())
    assert await reg.register(A, "chat", INITIATOR, Closer()) is not None


async def test_new_loser_is_closed_and_old_winner_stays():
    reg = DialRegistry(B)                  # B larger: connections dialed by A win
    old, new = Closer(), Closer()
    await reg.register(A, "chat", RESPONDER, old)          # dialed by A: winner
    assert await reg.register(A, "chat", INITIATOR, new) is None   # dialed by B: loser
    assert new.closed and not old.closed


async def test_new_winner_closes_old_loser():
    reg = DialRegistry(B)
    old, new = Closer(), Closer()
    loser = await reg.register(A, "chat", INITIATOR, old)  # dialed by B: will lose
    winner = await reg.register(A, "chat", RESPONDER, new) # dialed by A: wins
    assert winner is not None and old.closed and not new.closed
    assert loser.superseded and not winner.superseded


@pytest.mark.parametrize("order", list(itertools.permutations([0, 1])))
async def test_two_machines_end_up_with_the_same_connection_in_any_order(order):
    """Simulate both machines. c1 dialed by A, c2 dialed by B. Arrival order differs."""
    reg_a, reg_b = DialRegistry(A), DialRegistry(B)
    closers = {("A", 1): Closer(), ("A", 2): Closer(), ("B", 1): Closer(), ("B", 2): Closer()}
    views = {
        1: (("A", reg_a, A, B, INITIATOR), ("B", reg_b, B, A, RESPONDER)),
        2: (("A", reg_a, A, B, RESPONDER), ("B", reg_b, B, A, INITIATOR)),
    }
    for conn in (order[0] + 1, order[1] + 1):
        for name, reg, _me, peer, role in views[conn]:
            await reg.register(peer, "chat", role, closers[(name, conn)])
    survivors = {conn for conn in (1, 2)
                 if not closers[("A", conn)].closed and not closers[("B", conn)].closed}
    assert survivors == {1}                # A is smaller, so the connection A dialed survives
    assert closers[("A", 2)].closed and closers[("B", 2)].closed


async def test_unregister_frees_the_slot():
    reg = DialRegistry(B)
    h = await reg.register(A, "chat", RESPONDER, Closer())
    reg.unregister(h)
    assert reg.live_count() == 0
    # a later connection in the other direction is no longer a duplicate
    assert await reg.register(A, "chat", INITIATOR, Closer()) is not None


def test_unregister_none_and_twice_are_harmless():
    reg = DialRegistry(A)
    reg.unregister(None)
    assert reg.live_count() == 0


async def test_close_error_of_the_loser_does_not_break_the_winner():
    reg = DialRegistry(B)

    async def bad():
        raise RuntimeError("socket already gone")

    await reg.register(A, "chat", INITIATOR, bad)           # will lose
    assert await reg.register(A, "chat", RESPONDER, Closer()) is not None