"""Stress tests (B.2): many connections at once over real loopback TCP.

Size can be changed:   $env:STRESS_N=100; python -m pytest tests/test_stress.py -q -s
Every test must finish without a hang, an exception in a task, or leftover state.
"""

import asyncio
import gc
import os
import random
import tracemalloc

import pytest

from p2pssh.handshake import SessionKeys
from p2pssh.session import SecureSession, SessionError
from p2pssh.transport import Node

N = int(os.environ.get("STRESS_N", "50"))
MSGS = 20
K1, K2 = b"A" * 32, b"B" * 32


def keys(send, recv):
    return SessionKeys(send_key=send, recv_key=recv, peer_pub=b"\0" * 32,
                       peer_fingerprint="SHA256:test", session_id=b"\0" * 16)


async def start_echo_server(**kw):
    """Server: every connection is an encrypted session that echoes records back."""
    kw.setdefault("max_connections", 1000)
    kw.setdefault("max_per_ip", 1000)
    kw.setdefault("max_new_per_window", 100000)
    errors = []

    async def on_conn(conn):
        s = SecureSession(conn, keys(K2, K1))
        try:
            while True:
                await s.send(await s.recv())
        except SessionError:
            pass
        except Exception as e:             # anything else is a bug
            errors.append(e)
        finally:
            await s.close()

    node = Node(**kw)
    await node.listen("127.0.0.1", 0, on_conn)
    return node, errors


async def client_run(port, idx, msgs=MSGS):
    conn = await Node().dial("127.0.0.1", port)
    s = SecureSession(conn, keys(K1, K2))
    for i in range(msgs):
        payload = f"client {idx} message {i}".encode() * random.randint(1, 50)
        await s.send(payload)
        assert await asyncio.wait_for(s.recv(), 10) == payload
    await s.close()


async def wait_until_empty(server, timeout=5.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if not server.connections and not server._open_per_ip:
            return True
        await asyncio.sleep(0.05)
    return False


async def test_many_clients_talk_at_once():
    server, errors = await start_echo_server()
    await asyncio.wait_for(
        asyncio.gather(*(client_run(server.port, i) for i in range(N))), 60)
    assert await wait_until_empty(server), "connections or per-IP counters leaked"
    assert errors == []
    await server.close()


async def test_clients_that_vanish_without_goodbye():
    """Half the clients drop the TCP connection in the middle of a conversation."""
    server, errors = await start_echo_server()

    async def rude(i):
        conn = await Node().dial("127.0.0.1", server.port)
        s = SecureSession(conn, keys(K1, K2))
        await s.send(b"hello")
        await s.recv()
        conn._w.transport.abort()          # no FIN, no close handshake

    await asyncio.wait_for(asyncio.gather(
        *(rude(i) if i % 2 else client_run(server.port, i) for i in range(N))), 60)
    assert await wait_until_empty(server), "dead clients were not cleaned up"
    assert errors == []
    await server.close()


async def test_clients_that_connect_and_say_nothing():
    server, errors = await start_echo_server()
    idle = [await Node().dial("127.0.0.1", server.port) for _ in range(N)]
    await asyncio.sleep(0.3)
    assert len(server.connections) == N
    await asyncio.wait_for(client_run(server.port, 999), 10)       # others still served
    for c in idle:
        await c.close()
    assert await wait_until_empty(server)
    assert errors == []
    await server.close()


async def test_garbage_from_many_clients_does_not_crash_server():
    server, errors = await start_echo_server()

    async def garbage(i):
        conn = await Node().dial("127.0.0.1", server.port)
        for _ in range(5):
            await conn.send_frame(os.urandom(random.randint(0, 3000)))
        await conn.close()

    await asyncio.wait_for(asyncio.gather(*(garbage(i) for i in range(N))), 30)
    assert await wait_until_empty(server)
    await asyncio.wait_for(client_run(server.port, 1), 10)        # server still works
    assert errors == []
    await server.close()


async def test_connect_disconnect_loop_has_no_leak():
    """Many short connections one after another: counters and memory stay flat."""
    server, errors = await start_echo_server()
    for _ in range(3):                                            # warm up
        await client_run(server.port, 0, msgs=2)
    gc.collect()
    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    for i in range(N * 4):
        await client_run(server.port, i, msgs=2)
    assert await wait_until_empty(server)
    gc.collect()
    after = tracemalloc.take_snapshot()
    tracemalloc.stop()
    growth = sum(s.size_diff for s in after.compare_to(before, "filename"))
    assert growth < 2_000_000, f"memory grew by {growth} bytes over {N * 4} connections"
    assert errors == []
    await server.close()


async def test_no_task_is_left_running():
    base = {t for t in asyncio.all_tasks()}
    server, errors = await start_echo_server()
    await asyncio.wait_for(
        asyncio.gather(*(client_run(server.port, i, msgs=3) for i in range(N))), 60)
    assert await wait_until_empty(server)
    await server.close()
    await asyncio.sleep(0.2)
    leftover = [t for t in asyncio.all_tasks() - base
                if t is not asyncio.current_task() and not t.done()]
    assert leftover == [], f"tasks still running: {leftover}"


async def test_limits_hold_under_flood():
    """Real limits on: a flood from one IP is mostly refused, the server stays healthy."""
    server, errors = await start_echo_server(max_per_ip=5, max_new_per_window=10)

    async def attempt(i):
        try:
            conn = await Node().dial("127.0.0.1", server.port)
            s = SecureSession(conn, keys(K1, K2))
            await s.send(b"x")
            await asyncio.wait_for(s.recv(), 2)
            await asyncio.sleep(0.3)
            await s.close()
            return True
        except (SessionError, asyncio.TimeoutError):
            return False

    results = await asyncio.wait_for(asyncio.gather(*(attempt(i) for i in range(N))), 30)
    assert sum(results) <= 10                      # window limit
    assert await wait_until_empty(server)
    assert errors == []
    await server.close()