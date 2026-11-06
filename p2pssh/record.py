
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class RecordError(Exception):
    """Raised when a secure record is invalid."""


class RecordLayer:
    """
    AES-256-GCM record layer.

    Uses separate keys for sending and receiving.

    Wire format:
        8-byte sequence number + ciphertext + 16-byte GCM tag.

    Nonce:
        4-byte zero prefix + 8-byte sequence number.

    Each direction has a separate handshake-derived key.
    """

    MAX_SEQUENCE = (1 << 64) - 1

    SEQUENCE_SIZE = 8
    NONCE_PREFIX = b"\x00\x00\x00\x00"
    TAG_SIZE = 16

    def __init__(self, send_key: bytes, recv_key: bytes):
        if not isinstance(send_key, bytes) or len(send_key) != 32:
            raise ValueError("send_key must be exactly 32 bytes")

        if not isinstance(recv_key, bytes) or len(recv_key) != 32:
            raise ValueError("recv_key must be exactly 32 bytes")

        self.send_aes = AESGCM(send_key)
        self.recv_aes = AESGCM(recv_key)

        self.send_sequence = 0
        self.recv_sequence = 0

    def seal(self, plaintext: bytes) -> bytes:
        """Encrypt and authenticate one outgoing record."""

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        if self.send_sequence > self.MAX_SEQUENCE:
            raise RecordError("Send sequence number exhausted")

        sequence = struct.pack("!Q", self.send_sequence)

        nonce = self.NONCE_PREFIX + sequence

        ciphertext = self.send_aes.encrypt(
            nonce,
            plaintext,
            sequence,
        )

        self.send_sequence += 1

        return sequence + ciphertext

    def open(self, record: bytes) -> bytes:
        """Authenticate and decrypt one incoming record."""

        if not isinstance(record, bytes):
            raise TypeError("record must be bytes")

        if len(record) < self.SEQUENCE_SIZE + self.TAG_SIZE:
            raise RecordError("Record is too short")

        sequence = record[:self.SEQUENCE_SIZE]

        received_sequence = struct.unpack("!Q", sequence)[0]

        if received_sequence != self.recv_sequence:
            raise RecordError(
                f"Unexpected sequence: expected {self.recv_sequence}, "
                f"got {received_sequence}"
            )

        nonce = self.NONCE_PREFIX + sequence

        ciphertext = record[self.SEQUENCE_SIZE:]

        try:
            plaintext = self.recv_aes.decrypt(
                nonce,
                ciphertext,
                sequence,
            )

        except InvalidTag as exc:
            raise RecordError(
                "Authentication failed: record may be modified"
            ) from exc

        # Increment only after successful authentication.
        self.recv_sequence += 1

        return plaintext
