# p2pssh/transport.py
import asyncio
import struct

from .constants import MAX_FRAME_SIZE
from .errors import ConnectionClosed, FrameError, P2PSSHError


class Connection:
    def __init__(self, reader, writer):
        self._r, self._w = reader, writer
        self._wlock = asyncio.Lock()   # do tasks ek saath likhein to bytes mix na hon
        self.closed = False

    async def send_frame(self, data: bytes) -> None:
        if self.closed:
            raise ConnectionClosed("connection is closed")
        if len(data) > MAX_FRAME_SIZE:
            raise FrameError(f"frame too large: {len(data)}")
        async with self._wlock:
            self._w.write(struct.pack(">I", len(data)) + data)
            await self._w.drain()

    async def recv_frame(self) -> bytes:
        try:
            hdr = await self._r.readexactly(4)
            n = struct.unpack(">I", hdr)[0]
            if n > MAX_FRAME_SIZE:      # payload padhne se PEHLE check
                await self.close()
                raise FrameError(f"frame too large: {n}")
            return await self._r.readexactly(n) if n else b""
        except asyncio.IncompleteReadError:
            await self.close()
            raise ConnectionClosed("peer disconnected")

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._w.close()
        try:
            await self._w.wait_closed()
        except Exception:
            pass


class Node:
    def __init__(self):
        self._server = None
        self.port = None

    async def listen(self, host, port, on_conn):
        async def handler(r, w):
            conn = Connection(r, w)
            try:
                await on_conn(conn)
            finally:
                await conn.close()
        try:
            self._server = await asyncio.start_server(handler, host, port)
        except OSError as e:
            raise P2PSSHError(f"cannot listen on {host}:{port}: {e.strerror}")
        self.port = self._server.sockets[0].getsockname()[1]

    async def dial(self, host, port, timeout=5.0) -> Connection:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except asyncio.TimeoutError:
            raise P2PSSHError(f"timeout connecting to {host}:{port}")
        except OSError as e:
            raise P2PSSHError(f"cannot connect to {host}:{port}: {e.strerror}")
        return Connection(r, w)

    async def close(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()