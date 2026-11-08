import asyncio
import struct

import pytest

from p2pssh.shell import (TAG_EXIT, TAG_IN, TAG_OUT, TAG_RESIZE, pty_available,
                          serve_shell)

pytestmark = pytest.mark.skipif(not pty_available(), reason="shell needs a Unix pty")


class FakeSession:
    def __init__(self):
        self.inbox = asyncio.Queue()
        self.peer = None
        self.closed = False

    async def send(self, data: bytes):
        await self.peer.inbox.put(data)

    async def recv(self) -> bytes:
        return await asyncio.wait_for(self.inbox.get(), 5)


def pair():
    a, b = FakeSession(), FakeSession()
    a.peer, b.peer = b, a
    return a, b


async def read_until(client, needle: bytes, timeout=5):
    seen = b""
    async def loop():
        nonlocal seen
        while needle not in seen:
            msg = await client.recv()
            if msg[:1] == TAG_OUT:
                seen += msg[1:]
            elif msg[:1] == TAG_EXIT:
                return
    await asyncio.wait_for(loop(), timeout)
    return seen


async def test_commands_run_and_output_comes_back():
    client, host = pair()
    task = asyncio.ensure_future(serve_shell(host, shell="/bin/sh"))
    await client.send(TAG_IN + b"echo hello-$((6*7))\n")
    assert b"hello-42" in await read_until(client, b"hello-42")
    await client.send(TAG_IN + b"exit 3\n")
    exit_frame = None
    while exit_frame is None:
        msg = await client.recv()
        if msg[:1] == TAG_EXIT:
            exit_frame = msg
    assert exit_frame == TAG_EXIT + bytes([3])
    assert await asyncio.wait_for(task, 5) == 3


async def test_resize_is_applied():
    client, host = pair()
    task = asyncio.ensure_future(serve_shell(host, shell="/bin/sh"))
    await client.send(TAG_RESIZE + struct.pack(">HH", 30, 100))
    await client.send(TAG_IN + b"stty size\n")
    assert b"30 100" in await read_until(client, b"30 100")
    await client.send(TAG_IN + b"exit\n")
    await asyncio.wait_for(task, 5)


async def test_bad_resize_and_unknown_tags_are_ignored():
    client, host = pair()
    task = asyncio.ensure_future(serve_shell(host, shell="/bin/sh"))
    await client.send(TAG_RESIZE + b"\x00")                    # wrong length
    await client.send(TAG_RESIZE + struct.pack(">HH", 0, 0))   # out of range
    await client.send(b"Z" + b"junk")                          # unknown tag
    await client.send(b"")                                     # empty record
    await client.send(TAG_IN + b"echo still-alive\n")
    assert b"still-alive" in await read_until(client, b"still-alive")
    await client.send(TAG_IN + b"exit\n")
    await asyncio.wait_for(task, 5)


async def test_peer_disconnect_kills_the_shell():
    client, host = pair()

    async def recv_then_fail():
        raise ConnectionError("peer vanished")
    task = asyncio.ensure_future(serve_shell(host, shell="/bin/sh"))
    await client.send(TAG_IN + b"echo up\n")
    await read_until(client, b"up")
    host.recv = recv_then_fail                                 # next read fails like a dropped link
    await client.send(TAG_IN + b"echo trigger\n")
    with pytest.raises(ConnectionError):
        await asyncio.wait_for(task, 5)


async def test_large_output_is_split_into_small_records():
    client, host = pair()
    task = asyncio.ensure_future(serve_shell(host, shell="/bin/sh"))
    await client.send(TAG_IN + b"head -c 60000 /dev/zero | tr '\\0' 'x'; echo DONE\n")
    sizes = []
    seen = b""
    while b"DONE" not in seen:
        msg = await asyncio.wait_for(client.recv(), 5)
        if msg[:1] == TAG_OUT:
            sizes.append(len(msg))
            seen += msg[1:]
    assert max(sizes) <= 8 * 1024 + 1
    await client.send(TAG_IN + b"exit\n")
    await asyncio.wait_for(task, 5)