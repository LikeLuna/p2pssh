"""Per-IP connection limits in Node (p2pssh/transport.py)."""

import asyncio

import pytest

from p2pssh.errors import ConnectionClosed
from p2pssh.transport import Node


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


async def make_server(**kw):
    async def on_conn(conn):
        try:
            while True:
                await conn.recv_frame()
        except Exception:
            pass
    server = Node(**kw)
    await server.listen("127.0.0.1", 0, on_conn)
    return server


async def dial_open(server):
    c = await Node().dial("127.0.0.1", server.port)
    await asyncio.sleep(0.05)
    return c


async def test_concurrent_limit_per_ip():
    server = await make_server(max_per_ip=3, max_new_per_window=100)
    keep = [await dial_open(server) for _ in range(3)]
    assert len(server.connections) == 3
    extra = await Node().dial("127.0.0.1", server.port)
    with pytest.raises(ConnectionClosed):
        await asyncio.wait_for(extra.recv_frame(), 2)       # 4th is closed at once
    assert len(server.connections) == 3
    for c in keep:
        await c.close()
    await server.close()


async def test_slot_is_freed_when_a_connection_closes():
    server = await make_server(max_per_ip=2, max_new_per_window=100)
    a = await dial_open(server)
    b = await dial_open(server)
    await a.close()
    await asyncio.sleep(0.1)
    c = await dial_open(server)                              # freed slot is usable again
    assert len(server.connections) == 2
    assert server._open_per_ip == {"127.0.0.1": 2}
    for x in (b, c):
        await x.close()
    await server.close()


async def test_counter_returns_to_zero_after_all_close():
    server = await make_server(max_per_ip=2, max_new_per_window=100)
    cs = [await dial_open(server) for _ in range(2)]
    for c in cs:
        await c.close()
    await asyncio.sleep(0.1)
    assert server._open_per_ip == {}
    await server.close()


async def test_rate_limit_inside_window():
    clock = Clock()
    server = await make_server(max_per_ip=100, max_new_per_window=3, rate_window=60, clock=clock)
    for _ in range(3):                                       # open and close: slots are free,
        c = await dial_open(server)                          # but 3 accepts are used up
        await c.close()
        await asyncio.sleep(0.05)
    extra = await Node().dial("127.0.0.1", server.port)
    with pytest.raises(ConnectionClosed):
        await asyncio.wait_for(extra.recv_frame(), 2)
    await server.close()


async def test_rate_limit_resets_after_window():
    clock = Clock()
    server = await make_server(max_per_ip=100, max_new_per_window=2, rate_window=60, clock=clock)
    for _ in range(2):
        c = await dial_open(server)
        await c.close()
        await asyncio.sleep(0.05)
    clock.t += 61                                            # window is over
    c = await dial_open(server)
    assert len(server.connections) == 1
    await c.close()
    await server.close()


async def test_just_inside_window_is_still_limited():
    clock = Clock()
    server = await make_server(max_per_ip=100, max_new_per_window=1, rate_window=60, clock=clock)
    c = await dial_open(server)
    await c.close()
    await asyncio.sleep(0.05)
    clock.t += 59
    extra = await Node().dial("127.0.0.1", server.port)
    with pytest.raises(ConnectionClosed):
        await asyncio.wait_for(extra.recv_frame(), 2)
    await server.close()


async def test_rejected_attempts_do_not_extend_the_block():
    clock = Clock()
    server = await make_server(max_per_ip=100, max_new_per_window=1, rate_window=60, clock=clock)
    c = await dial_open(server)
    await c.close()
    await asyncio.sleep(0.05)
    for _ in range(5):                                       # hammering while blocked
        clock.t += 10
        extra = await Node().dial("127.0.0.1", server.port)
        with pytest.raises(ConnectionClosed):
            await asyncio.wait_for(extra.recv_frame(), 2)
    clock.t += 15                                            # 65 s after the one accepted connection
    c = await dial_open(server)
    assert len(server.connections) == 1
    await c.close()
    await server.close()


def test_admit_tracks_ips_separately():
    node = Node(max_per_ip=1, max_new_per_window=100)
    assert node._admit("1.1.1.1")
    assert not node._admit("1.1.1.1")
    assert node._admit("2.2.2.2")                            # other IP is not affected
    node._release("1.1.1.1")
    assert node._admit("1.1.1.1")


def test_release_of_unknown_ip_is_harmless():
    node = Node()
    node._release("9.9.9.9")
    assert node._open_per_ip == {}


def test_old_ips_are_forgotten():
    clock = Clock()
    node = Node(max_per_ip=10, max_new_per_window=10, rate_window=60, clock=clock)
    for i in range(1100):
        node._admit(f"10.0.{i // 250}.{i % 250}")
        node._release(f"10.0.{i // 250}.{i % 250}")
    clock.t += 120
    node._admit("5.5.5.5")
    assert len(node._recent) < 100                           # table did not grow without bound


async def test_total_limit_still_works_with_per_ip_limits():
    server = await make_server(max_connections=2, max_per_ip=100, max_new_per_window=100)
    a = await dial_open(server)
    b = await dial_open(server)
    c = await Node().dial("127.0.0.1", server.port)
    with pytest.raises(ConnectionClosed):
        await asyncio.wait_for(c.recv_frame(), 2)
    assert server._open_per_ip == {"127.0.0.1": 2}           # rejected one was not counted
    for x in (a, b):
        await x.close()
    await server.close()


async def test_default_limits_allow_normal_use():
    server = await make_server()
    cs = [await dial_open(server) for _ in range(3)]
    assert len(server.connections) == 3
    for c in cs:
        await c.close()
    await server.close()


def test_window_boundary_is_exact():
    clock = Clock()
    node = Node(max_per_ip=100, max_new_per_window=1, rate_window=60, clock=clock)
    assert node._admit("1.1.1.1")
    node._release("1.1.1.1")
    clock.t += 59.9
    assert not node._admit("1.1.1.1")
    clock.t += 0.1                                           # exactly 60 s: the old entry has expired
    assert node._admit("1.1.1.1")