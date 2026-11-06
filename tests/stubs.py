
"""Reusable asynchronous test doubles for P2PSSH."""

import asyncio


class StubConnection:
    """In-memory replacement for transport.Connection."""

    def __init__(self, incoming=None, outgoing=None, peer_name=None):
        self.incoming = incoming if incoming is not None else asyncio.Queue()
        self.outgoing = outgoing if outgoing is not None else asyncio.Queue()
        self.peer_name = peer_name
        self.closed = False

    async def send_frame(self, data: bytes) -> None:
        if self.closed:
            raise RuntimeError("Connection is closed")

        if not isinstance(data, bytes):
            raise TypeError("Frame must be bytes")

        await self.outgoing.put(data)

    async def recv_frame(self, timeout=None) -> bytes:
        if self.closed:
            raise RuntimeError("Connection is closed")

        try:
            if timeout is None:
                data = await self.incoming.get()
            else:
                data = await asyncio.wait_for(
                    self.incoming.get(), timeout
                )
        except asyncio.TimeoutError:
            await self.close()
            raise

        if data is None:
            self.closed = True
            raise RuntimeError("Peer disconnected")

        return data

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            await self.outgoing.put(None)

    @classmethod
    def pair(cls):
        """Create two connected in-memory connections."""
        a_to_b = asyncio.Queue()
        b_to_a = asyncio.Queue()

        a = cls(incoming=b_to_a, outgoing=a_to_b)
        b = cls(incoming=a_to_b, outgoing=b_to_a)

        return a, b


class StubSession:
    """In-memory replacement for SecureSession."""

    def __init__(self, incoming=None, outgoing=None):
        self.incoming = incoming if incoming is not None else asyncio.Queue()
        self.outgoing = outgoing if outgoing is not None else asyncio.Queue()
        self.closed = False

    async def send(self, data: bytes) -> None:
        if self.closed:
            raise RuntimeError("Session is closed")

        if not isinstance(data, bytes):
            raise TypeError("Message must be bytes")

        await self.outgoing.put(data)

    async def recv(self) -> bytes:
        if self.closed:
            raise RuntimeError("Session is closed")

        data = await self.incoming.get()

        if data is None:
            self.closed = True
            raise RuntimeError("Peer disconnected")

        return data

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            await self.outgoing.put(None)

    @classmethod
    def pair(cls):
        """Create two connected in-memory sessions."""
        a_to_b = asyncio.Queue()
        b_to_a = asyncio.Queue()

        a = cls(incoming=b_to_a, outgoing=a_to_b)
        b = cls(incoming=a_to_b, outgoing=b_to_a)

        return a, b
