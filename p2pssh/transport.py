import asyncio
import struct
import time
from collections import deque

from .constants import (MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, MAX_FRAME_SIZE,
                        MAX_NEW_PER_WINDOW, RATE_WINDOW)
from .errors import ConnectionClosed, ConnTimeout, FrameError, P2PSSHError


class Connection:
    def __init__(self, reader, writer, peer_name=None):
        self._r, self._w = reader, writer
        self._wlock = asyncio.Lock()
        self.closed = False
        self.peer_name = peer_name   # sirf label; asli identity fingerprint hai

    async def send_frame(self, data: bytes) -> None:
        if self.closed:
            raise ConnectionClosed("connection is closed")
        if len(data) > MAX_FRAME_SIZE:
            raise FrameError(f"frame too large: {len(data)}")
        async with self._wlock:
            self._w.write(struct.pack(">I", len(data)) + data)
            await self._w.drain()

    async def _recv(self) -> bytes:
        try:
            hdr = await self._r.readexactly(4)
            n = struct.unpack(">I", hdr)[0]
            if n > MAX_FRAME_SIZE:          # payload padhne se PEHLE check
                await self.close()
                raise FrameError(f"frame too large: {n}")
            return await self._r.readexactly(n) if n else b""
        except asyncio.IncompleteReadError:
            await self.close()
            raise ConnectionClosed("peer disconnected")

    async def recv_frame(self, timeout=None) -> bytes:
        try:
            if timeout is None:
                return await self._recv()
            return await asyncio.wait_for(self._recv(), timeout)
        except asyncio.TimeoutError:
            await self.close()   # aadha padha stream dobara use nahi ho sakta
            raise ConnTimeout(f"no data within {timeout}s")

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
    def __init__(self, max_connections=MAX_CONNECTIONS,
                 max_per_ip=MAX_CONNECTIONS_PER_IP,
                 max_new_per_window=MAX_NEW_PER_WINDOW,
                 rate_window=RATE_WINDOW, clock=time.monotonic):
        self._server = None
        self.port = None
        self.max_connections = max_connections
        self.max_per_ip = max_per_ip
        self.max_new_per_window = max_new_per_window
        self.rate_window = rate_window
        self._clock = clock                 # tests can pass a fake clock
        self.connections = set()      # registry (`status` command ke liye)
        self._open_per_ip = {}        # ip -> connections open right now
        self._recent = {}             # ip -> deque of accept times inside the window

    def _admit(self, ip) -> bool:
        """Per-IP limits. True = accept (and count it), False = reject.

        Only accepted connections are counted in the window, so a rejected
        attempt costs the attacker nothing extra but also costs us nothing."""
        now = self._clock()
        if len(self._recent) > 1024:                 # forget IPs that went quiet
            for k in [k for k, q in self._recent.items()
                      if not q or now - q[-1] >= self.rate_window]:
                del self._recent[k]
        times = self._recent.setdefault(ip, deque())
        while times and now - times[0] >= self.rate_window:
            times.popleft()
        if self._open_per_ip.get(ip, 0) >= self.max_per_ip:
            return False
        if len(times) >= self.max_new_per_window:
            return False
        times.append(now)
        self._open_per_ip[ip] = self._open_per_ip.get(ip, 0) + 1
        return True

    def _release(self, ip) -> None:
        n = self._open_per_ip.get(ip, 0) - 1
        if n > 0:
            self._open_per_ip[ip] = n
        else:
            self._open_per_ip.pop(ip, None)

    async def listen(self, host, port, on_conn):
        async def handler(r, w):
            conn = Connection(r, w)
            if len(self.connections) >= self.max_connections:
                await conn.close()    # zyada connections: politely reject
                return
            peer = w.get_extra_info("peername")
            ip = peer[0] if peer else "?"
            if not self._admit(ip):
                await conn.close()    # this IP is over its limit
                return
            self.connections.add(conn)
            try:
                await on_conn(conn)
            finally:
                self.connections.discard(conn)
                self._release(ip)
                await conn.close()
        try:
            self._server = await asyncio.start_server(handler, host, port)
        except OSError as e:
            raise P2PSSHError(f"cannot listen on {host}:{port}: {e.strerror}")
        self.port = self._server.sockets[0].getsockname()[1]

    async def dial(self, host, port, timeout=5.0, name=None) -> Connection:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except asyncio.TimeoutError:
            raise P2PSSHError(f"timeout connecting to {host}:{port}")
        except OSError as e:
            raise P2PSSHError(f"cannot connect to {host}:{port}: {e.strerror}")
        return Connection(r, w, peer_name=name or f"{host}:{port}")

    async def close(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()