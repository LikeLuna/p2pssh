import asyncio
import struct

import pytest

from p2pssh.errors import ConnectionClosed, ConnTimeout, FrameError, P2PSSHError
from p2pssh.transport import Node


async def echo_server(**kw):
    async def on_conn(conn):
        try:
            while True:
                await conn.send_frame(await conn.recv_frame())
        except Exception:
            pass
    node = Node(**kw)
    await node.listen("127.0.0.1", 0, on_conn)
    return node


async def test_B2_N1_echo():
    server = await echo_server()
    c = await Node().dial("127.0.0.1", server.port)
    await c.send_frame(b"hello")
    assert await c.recv_frame() == b"hello"
    await c.close()
    await server.close()


async def test_zero_length_frame():
    server = await echo_server()
    c = await Node().dial("127.0.0.1", server.port)
    await c.send_frame(b"")
    assert await c.recv_frame() == b""
    await c.close()
    await server.close()


async def test_65537_rejected():
    server = await echo_server()
    c = await Node().dial("127.0.0.1", server.port)
    with pytest.raises(FrameError):
        await c.send_frame(b"x" * 65537)
    await c.close()
    await server.close()


async def test_send_after_close():
    server = await echo_server()
    c = await Node().dial("127.0.0.1", server.port)
    await c.close()
    with pytest.raises(ConnectionClosed):
        await c.send_frame(b"x")
    await server.close()

# ---------------- boundary ----------------
async def test_frame_split_into_single_bytes():
    server = await echo_server()
    r, w = await asyncio.open_connection("127.0.0.1", server.port)
    data = struct.pack(">I", 5) + b"hello"
    for b in data:
        w.write(bytes([b])); await w.drain()
        await asyncio.sleep(0.001)
    assert await r.readexactly(9) == data
    w.close(); await server.close()


async def test_two_frames_in_one_write():
    server = await echo_server()
    r, w = await asyncio.open_connection("127.0.0.1", server.port)
    w.write(struct.pack(">I", 3) + b"one" + struct.pack(">I", 3) + b"two")
    await w.drain()
    assert await r.readexactly(14) == struct.pack(">I", 3) + b"one" + struct.pack(">I", 3) + b"two"
    w.close(); await server.close()


async def test_header_4GB_rejected():
    server = await echo_server()
    r, w = await asyncio.open_connection("127.0.0.1", server.port)
    w.write(b"\xff\xff\xff\xff"); await w.drain()
    assert await asyncio.wait_for(r.read(1), 2) == b""
    w.close(); await server.close()


async def test_exact_max_frame_ok():
    server = await echo_server()
    c = await Node().dial("127.0.0.1", server.port)
    await c.send_frame(b"x" * 65536)
    assert len(await c.recv_frame()) == 65536
    await c.close(); await server.close()


async def test_1000_frames_in_order():
    server = await echo_server()
    c = await Node().dial("127.0.0.1", server.port)
    for i in range(1000):
        await c.send_frame(str(i).encode())
    for i in range(1000):
        assert await c.recv_frame() == str(i).encode()
    await c.close(); await server.close()


async def test_disconnect_mid_payload():
    got = []
    async def on_conn(conn):
        try:
            await conn.recv_frame()
        except ConnectionClosed:
            got.append("closed")
    server = Node()
    await server.listen("127.0.0.1", 0, on_conn)
    r, w = await asyncio.open_connection("127.0.0.1", server.port)
    w.write(struct.pack(">I", 100) + b"only-part"); await w.drain()
    w.close()
    await asyncio.sleep(0.2)
    assert got == ["closed"]
    await server.close()


async def test_connection_refused_clear_error():
    with pytest.raises(P2PSSHError):
        await Node().dial("127.0.0.1", 1, timeout=1)


async def test_port_in_use():
    async def noop(c):
        pass
    a = Node()
    await a.listen("127.0.0.1", 0, noop)
    with pytest.raises(P2PSSHError):
        await Node().listen("127.0.0.1", a.port, noop)
    await a.close()


async def test_concurrent_senders_do_not_mix_bytes():
    server = await echo_server()
    c = await Node().dial("127.0.0.1", server.port)
    msgs = [bytes([i]) * 5000 for i in range(20)]
    await asyncio.gather(*(c.send_frame(m) for m in msgs))
    got = [await c.recv_frame() for _ in msgs]
    assert sorted(got) == sorted(msgs)
    await c.close(); await server.close()


# ---------------- limits ----------------
async def test_connection_limit():
    async def on_conn(conn):
        try:
            while True:
                await conn.recv_frame()
        except Exception:
            pass
    server = Node(max_connections=2)
    await server.listen("127.0.0.1", 0, on_conn)
    a = await Node().dial("127.0.0.1", server.port)
    b = await Node().dial("127.0.0.1", server.port)
    await asyncio.sleep(0.1)
    c = await Node().dial("127.0.0.1", server.port)     # 3rd reject hona chahiye
    with pytest.raises(ConnectionClosed):
        await asyncio.wait_for(c.recv_frame(), 2)
    await a.close(); await asyncio.sleep(0.1)           # ek jagah khali
    d = await Node().dial("127.0.0.1", server.port)
    await asyncio.sleep(0.1)
    assert len(server.connections) == 2                 # b aur d
    for x in (b, d):
        await x.close()
    await server.close()


async def test_silent_client_times_out():
    result = []
    async def on_conn(conn):
        try:
            await conn.recv_frame(timeout=0.3)
        except ConnTimeout:
            result.append("timeout")
    server = Node()
    await server.listen("127.0.0.1", 0, on_conn)
    r, w = await asyncio.open_connection("127.0.0.1", server.port)   # connect kiya, kuch nahi bheja
    assert await asyncio.wait_for(r.read(1), 3) == b""               # server ne band kar diya
    assert result == ["timeout"]
    w.close(); await server.close()


async def test_half_header_times_out():
    result = []
    async def on_conn(conn):
        try:
            await conn.recv_frame(timeout=0.3)
        except ConnTimeout:
            result.append("timeout")
    server = Node()
    await server.listen("127.0.0.1", 0, on_conn)
    r, w = await asyncio.open_connection("127.0.0.1", server.port)
    w.write(b"\x00\x00"); await w.drain()                            # 4 mein se sirf 2 header bytes
    assert await asyncio.wait_for(r.read(1), 3) == b""
    assert result == ["timeout"]
    w.close(); await server.close()


async def test_dial_sets_peer_name():
    server = await echo_server()
    c = await Node().dial("127.0.0.1", server.port)
    assert c.peer_name == f"127.0.0.1:{server.port}"
    c2 = await Node().dial("127.0.0.1", server.port, name="laptopA")
    assert c2.peer_name == "laptopA"
    await c.close(); await c2.close(); await server.close()