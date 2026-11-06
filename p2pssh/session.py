
import asyncio

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
                record = await self.conn.recv_frame()

                if not isinstance(record, bytes):
                    raise SessionError("Received frame must be bytes")

                if not (
                    self.MIN_RECORD_SIZE
                    <= len(record)
                    <= self.MAX_RECORD_SIZE
                ):
                    raise SessionError("Invalid record length")

                return self.record_layer.open(record)

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

    async def close(self) -> None:
        """Close the underlying connection."""

        if self.closed:
            return

        self.closed = True

        try:
            await self.conn.close()
        except Exception:
            pass
