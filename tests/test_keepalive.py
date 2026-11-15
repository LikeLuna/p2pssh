"""Keepalive: an empty encrypted record is a ping (p2pssh/session.py)."""

import asyncio

import pytest

from p2pssh.handshake import SessionKeys
from p2pssh.session import SecureSession, SessionError
from p2pssh.transport import Node

K1, K2 = b"A" * 32, b"B" * 32


def keys(send, recv):
    return SessionKeys(send_key=send, recv_key=recv, peer_pub=b"\0" * 32,
                       peer_fingerprint="SHA256:test", session_id=b"\0" * 16)


async def make_pair():
    """Two SecureSessions over a real loopback TCP connection."""
    got = asyncio.get_running_loop().create_future()
    hold = asyncio.Event()

    async def on_conn(conn):
        got.set_result(conn)
        await hold.wait()

    node = Node()
    await node.listen("127.0.0.1", 0, on_conn)
    client_conn = await Node().dial("127.0.0.1", node.port)
    server_conn = await got
    a = SecureSession(client_conn, keys(K1, K2))
    b = SecureSession(server_conn, keys(K2, K1))
    return a, b, node, hold


async def cleanup(a, b, node, hold):
    hold.set()
    await a.close()
    await b.close()
    await node.close()


async def test_pings_are_invisible_to_the_application():
    a, b, node, hold = await make_pair()
    a.start_keepalive(interval=0.05, idle_timeout=5)
    await asyncio.sleep(0.4)                 # several pings are on the wire now
    await a.send(b"real message")
    assert await asyncio.wait_for(b.recv(), 2) == b"real message"
    await cleanup(a, b, node, hold)


async def test_pings_are_actually_sent():
    a, b, node, hold = await make_pair()
    a.start_keepalive(interval=0.05, idle_timeout=5)
    await asyncio.sleep(0.4)
    assert b.conn._r._buffer, "peer should have received ping records"   # unread bytes waiting
    await cleanup(a, b, node, hold)


async def test_connection_with_keepalive_survives_long_silence():
    a, b, node, hold = await make_pair()
    a.start_keepalive(interval=0.05, idle_timeout=0.3)
    b.start_keepalive(interval=0.05, idle_timeout=0.3)
    reader = asyncio.create_task(b.recv())
    await asyncio.sleep(1.0)                 # 3x idle_timeout with no app data
    assert not b.closed and not reader.done()
    await a.send(b"still here")
    assert await asyncio.wait_for(reader, 2) == b"still here"
    await cleanup(a, b, node, hold)


async def test_silent_peer_is_closed_after_idle_timeout():
    a, b, node, hold = await make_pair()
    b.start_keepalive(interval=0.05, idle_timeout=0.3)   # a never pings
    reader = asyncio.create_task(b.recv())
    with pytest.raises(SessionError):
        await asyncio.wait_for(reader, 3)
    assert b.closed
    await cleanup(a, b, node, hold)


async def test_no_idle_close_when_nobody_is_waiting():
    """A side that is busy sending (not in recv) must not be closed as idle."""
    a, b, node, hold = await make_pair()
    b.start_keepalive(interval=10, idle_timeout=0.2)
    await asyncio.sleep(0.8)
    assert not b.closed
    await cleanup(a, b, node, hold)


async def test_idle_clock_starts_when_recv_starts_waiting():
    a, b, node, hold = await make_pair()
    b.start_keepalive(interval=10, idle_timeout=0.4)
    await asyncio.sleep(0.8)                 # long quiet time before anyone calls recv
    reader = asyncio.create_task(b.recv())
    await asyncio.sleep(0.2)
    assert not b.closed                      # only 0.2 s of waiting so far
    await a.send(b"late")
    assert await asyncio.wait_for(reader, 2) == b"late"
    await cleanup(a, b, node, hold)


async def test_close_stops_the_keepalive_task():
    a, b, node, hold = await make_pair()
    a.start_keepalive(interval=0.05, idle_timeout=5)
    task = a._keepalive_task
    await a.close()
    await asyncio.sleep(0.1)
    assert task.done()
    await cleanup(a, b, node, hold)


async def test_start_keepalive_twice_makes_one_task():
    a, b, node, hold = await make_pair()
    a.start_keepalive(interval=1, idle_timeout=5)
    first = a._keepalive_task
    a.start_keepalive(interval=1, idle_timeout=5)
    assert a._keepalive_task is first
    await cleanup(a, b, node, hold)


async def test_start_keepalive_on_closed_session_does_nothing():
    a, b, node, hold = await make_pair()
    await a.close()
    a.start_keepalive()
    assert a._keepalive_task is None
    await cleanup(a, b, node, hold)


async def test_forged_ping_is_rejected():
    """An attacker cannot inject a ping: unauthenticated bytes close the session."""
    a, b, node, hold = await make_pair()
    await a.conn.send_frame(b"\x00" * 40)    # not a valid encrypted record
    with pytest.raises(SessionError):
        await asyncio.wait_for(b.recv(), 2)
    await cleanup(a, b, node, hold)


async def test_empty_frame_is_not_a_ping():
    a, b, node, hold = await make_pair()
    await a.conn.send_frame(b"")             # too short to be a record
    with pytest.raises(SessionError):
        await asyncio.wait_for(b.recv(), 2)
    await cleanup(a, b, node, hold)


async def test_ping_counter_stays_in_step_with_data():
    """Pings use record counters; data after many pings must still decrypt."""
    a, b, node, hold = await make_pair()
    for _ in range(5):
        await a.send(b"")
    await a.send(b"after pings")
    assert await asyncio.wait_for(b.recv(), 2) == b"after pings"
    await cleanup(a, b, node, hold)