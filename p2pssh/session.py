import asyncio
import time

from .constants import IDLE_TIMEOUT, PING_INTERVAL
from .record import RecordLayer, RecordError


class SessionError(Exception):
    """Raised when a secure session cannot safely continue."""


class SecureSession:
    """Asynchronous encrypted session over a frame connection."""

    MAX_RECORD_SIZE = 16 * 1024
    MIN_RECORD_SIZE = 8 + 16

    def __init__(self, conn, keys):
        self.conn = conn

        self.record_layer = RecordLayer(
            send_key=keys.send_key,
            recv_key=keys.recv_key,
        )

        self.send_lock = asyncio.Lock()
        self.recv_lock = asyncio.Lock()
        self.closed = False

        # keepalive (see start_keepalive); an empty record is a ping
        self._keepalive_task = None
        self._last_rx = time.monotonic()
        self._waiting_since = None      # set while recv() waits for the peer
        self._last_tx = time.monotonic()

    async def send(self, data: bytes) -> None:
        """Encrypt and send one record."""

        if self.closed:
            raise SessionError("Session is closed")

        if not isinstance(data, bytes):
            raise TypeError("SecureSession.send() accepts bytes only")

        max_plaintext = self.MAX_RECORD_SIZE - self.MIN_RECORD_SIZE

        if len(data) > max_plaintext:
            raise SessionError(
                f"Maximum plaintext size is {max_plaintext} bytes"
            )

        async with self.send_lock:
            if self.closed:
                raise SessionError("Session is closed")

            try:
                record = self.record_layer.seal(data)
                await self.conn.send_frame(record)
                self._last_tx = time.monotonic()

            except asyncio.CancelledError:
                await self.close()
                raise

            except Exception as exc:
                await self.close()
                raise SessionError("Failed to send secure record") from exc

    async def recv(self) -> bytes:
        """Receive and authenticate one encrypted record."""

        if self.closed:
            raise SessionError("Session is closed")

        async with self.recv_lock:
            if self.closed:
                raise SessionError("Session is closed")

            try:
                self._waiting_since = time.monotonic()
                while True:
                    record = await self.conn.recv_frame()
                    self._last_rx = time.monotonic()

                    if not isinstance(record, bytes):
                        raise SessionError("Received frame must be bytes")

                    if not (
                        self.MIN_RECORD_SIZE
                        <= len(record)
                        <= self.MAX_RECORD_SIZE
                    ):
                        raise SessionError("Invalid record length")

                    data = self.record_layer.open(record)
                    if data:
                        return data
                    # empty record = keepalive ping: authenticated, never
                    # shown to the application, keep waiting for real data

            except asyncio.CancelledError:
                await self.close()
                raise

            except RecordError as exc:
                await self.close()
                raise SessionError(
                    "Record authentication or sequence validation failed"
                ) from exc

            except SessionError:
                await self.close()
                raise

            except Exception as exc:
                await self.close()
                raise SessionError("Failed to receive secure record") from exc

            finally:
                self._waiting_since = None

    def start_keepalive(self, interval: float = PING_INTERVAL,
                        idle_timeout: float = IDLE_TIMEOUT) -> None:
        """Send a ping every `interval` seconds of silence and close the session
        if the peer sends nothing for `idle_timeout` seconds while we wait for it.

        A ping is an empty encrypted record, so it is authenticated like any other
        record and an attacker cannot fake it. recv() swallows pings.
        The idle check only runs while some task is waiting in recv(); a side that
        is busy sending (for example a long file upload) is never closed for being
        "idle".  Call once, from inside a running event loop.
        """
        if self._keepalive_task is not None or self.closed:
            return
        self._keepalive_task = asyncio.create_task(
            self._keepalive_loop(interval, idle_timeout)
        )

    async def _keepalive_loop(self, interval: float, idle_timeout: float) -> None:
        tick = max(min(interval, idle_timeout) / 4, 0.01)
        while not self.closed:
            await asyncio.sleep(tick)
            now = time.monotonic()
            waiting = self._waiting_since
            if waiting is not None and now - max(self._last_rx, waiting) >= idle_timeout:
                await self.close()                    # peer is silent: give up
                return
            if now - self._last_tx >= interval:
                try:
                    await self.send(b"")              # ping
                except (SessionError, TypeError):
                    return

    async def close(self) -> None:
        """Close the underlying connection."""

        if self.closed:
            return

        self.closed = True

        task = self._keepalive_task
        if task is not None and task is not asyncio.current_task():
            task.cancel()

        try:
            await self.conn.close()
        except Exception:
            pass
