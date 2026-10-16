"""A.1: Identity management (owner: Member 1)."""
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_DIR = Path.home() / ".p2pssh"
PRIVATE_NAME = "id_ed25519"
PUBLIC_NAME = "id_ed25519.pub"


class Identity:
    """A node's permanent ID card: one Ed25519 key pair."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self.private_key = private_key
        self.public_key = private_key.public_key()

    def public_bytes(self) -> bytes:
        """The 32 raw bytes of the public key."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def _write_private(path: Path, key: Ed25519PrivateKey) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # O_EXCL: fail instead of overwriting an existing key.
    # 0o600: owner read/write only (ignored on native Windows).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def _write_public(path: Path, key: Ed25519PrivateKey) -> None:
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_or_create_identity(path: str = None) -> Identity:
    """Load the identity from folder `path`, creating it on first run."""
    folder = Path(path) if path else DEFAULT_DIR
    folder.mkdir(parents=True, exist_ok=True)

    private_path = folder / PRIVATE_NAME
    public_path = folder / PUBLIC_NAME

    if private_path.exists():
        pem = private_path.read_bytes()
        key = serialization.load_pem_private_key(pem, password=None)
        return Identity(key)

    key = Ed25519PrivateKey.generate()
    _write_private(private_path, key)
    _write_public(public_path, key)
    return Identity(key)