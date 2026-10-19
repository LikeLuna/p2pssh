
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class RecordError(Exception):
    """Raised when a secure record is invalid."""


class RecordLayer:
    """
    Encrypts and authenticates records.
    Each direction must have its own key and nonce prefix.
    """

    MAX_SEQUENCE = (1 << 64) - 1

    def __init__(self, key: bytes, nonce_prefix: bytes):
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")

        if len(nonce_prefix) != 4:
            raise ValueError("Nonce prefix must be exactly 4 bytes")

        self.aes = AESGCM(key)
        self.nonce_prefix = nonce_prefix
        self.send_sequence = 0
        self.recv_sequence = 0

    def seal(self, plaintext: bytes) -> bytes:
        """Encrypt one message and add its sequence number."""
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        if self.send_sequence > self.MAX_SEQUENCE:
            raise RecordError("Sequence number exhausted")

        sequence = struct.pack("!Q", self.send_sequence)
        nonce = self.nonce_prefix + sequence

        # Sequence number is authenticated, but not encrypted.
        ciphertext = self.aes.encrypt(
            nonce,
            plaintext,
            sequence,
        )

        self.send_sequence += 1

        # Wire format: 8-byte sequence + ciphertext + GCM tag
        return sequence + ciphertext

    def open(self, record: bytes) -> bytes:
        """Verify and decrypt one record in strict sequence order."""
        if len(record) < 8 + 16:
            raise RecordError("Record is too short")

        sequence = record[:8]
        received_number = struct.unpack("!Q", sequence)[0]

        if received_number != self.recv_sequence:
            raise RecordError(
                f"Unexpected sequence: expected {self.recv_sequence}, "
                f"got {received_number}"
            )

        nonce = self.nonce_prefix + sequence
        ciphertext = record[8:]

        try:
            plaintext = self.aes.decrypt(
                nonce,
                ciphertext,
                sequence,
            )
        except InvalidTag as exc:
            raise RecordError(
                "Authentication failed: record may be modified"
            ) from exc

        # Advance only after successful authentication.
        self.recv_sequence += 1
        return plaintext
