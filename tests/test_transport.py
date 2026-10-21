import asyncio

import pytest

from p2pssh.errors import ConnectionClosed, FrameError
from p2pssh.transport import Node


async def echo_server():
    async def on_conn(conn):
        try:
            while True:
                await conn.send_frame(await conn.recv_frame())
        except Exception:
            pass
    node = Node()
    await node.listen("127.0.0.1", 0, on_conn)   # port 0 = OS khud free port dega
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