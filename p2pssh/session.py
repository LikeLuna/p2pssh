
import socket
import struct
import threading

from record import RecordLayer


class SessionError(Exception):
    """Raised when a session cannot safely continue."""


class Session:
    MAX_RECORD_SIZE = 16 * 1024 * 1024  # 16 MiB

    def __init__(
        self,
        sock: socket.socket,
        send_key: bytes,
        recv_key: bytes,
        send_nonce_prefix: bytes,
        recv_nonce_prefix: bytes,
    ):
        self.sock = sock

        self.sender = RecordLayer(send_key, send_nonce_prefix)
        self.receiver = RecordLayer(recv_key, recv_nonce_prefix)

        self.send_lock = threading.Lock()
        self.recv_lock = threading.Lock()

    def send(self, data: bytes) -> None:
        """Encrypt data and send one length-prefixed record."""
        if not isinstance(data, bytes):
            raise TypeError("Session.send() accepts bytes only")

        with self.send_lock:
            record = self.sender.seal(data)

            if len(record) > self.MAX_RECORD_SIZE:
                raise SessionError("Record is too large")

            frame = struct.pack("!I", len(record)) + record
            self.sock.sendall(frame)

    def _recv_exact(self, size: int) -> bytes:
        """Read exactly size bytes or fail if the peer disconnects."""
        chunks = []
        remaining = size

        while remaining > 0:
            chunk = self.sock.recv(remaining)

            if not chunk:
                raise ConnectionError("Peer disconnected")

            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)

    def recv(self) -> bytes:
        """Receive one complete record, then authenticate and decrypt it."""
        with self.recv_lock:
            header = self._recv_exact(4)
            record_size = struct.unpack("!I", header)[0]

            if record_size < 24 or record_size > self.MAX_RECORD_SIZE:
                raise SessionError("Invalid record length")

            record = self._recv_exact(record_size)
            return self.receiver.open(record)

    def close(self) -> None:
        self.sock.close()
