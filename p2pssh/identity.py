"""A.1: Identity management (owner: Member 1)."""
import os
import stat
from pathlib import Path
import hmac
import json
import tempfile
import threading
import base64
import hashlib
from datetime import datetime, timezone
from enum import Enum
from cryptography.exceptions import UnsupportedAlgorithm

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
DEFAULT_DIR = Path.home() / ".p2pssh"
PRIVATE_NAME = "id_ed25519"
PUBLIC_NAME = "id_ed25519.pub"


class IdentityError(Exception):
    """Raised when the identity key cannot be loaded safely."""


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
    def sign(self, data: bytes) -> bytes:
        """Sign `data`; returns a 64-byte signature."""
        return self.private_key.sign(data)   


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


def _check_permissions(path: Path) -> None:
    """Refuse a private key that other users could read (like SSH)."""
    if os.name == "nt":
        return  # Windows permissions work differently; skip.
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise IdentityError(
            f"Private key {path} has unsafe permissions ({oct(mode)}). "
            f"Run: chmod 600 {path}"
        )


def _load_private(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise IdentityError(
            f"Private key {path} is corrupted or encrypted. "
            f"The file was NOT modified."
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityError(f"{path} is not an Ed25519 key. The file was NOT modified.")
    return key


def load_or_create_identity(path: str = None) -> Identity:
    """Load the identity from folder `path`, creating it on first run."""
    folder = Path(path) if path else DEFAULT_DIR
    folder.mkdir(parents=True, exist_ok=True)

    private_path = folder / PRIVATE_NAME
    public_path = folder / PUBLIC_NAME

    if private_path.exists():
        _check_permissions(private_path)
        key = _load_private(private_path)
        if not public_path.exists():          # recreate a lost .pub file
            _write_public(public_path, key)
        return Identity(key)

    key = Ed25519PrivateKey.generate()
    _write_private(private_path, key)
    _write_public(public_path, key)
    return Identity(key)
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64


def fingerprint(pub: bytes) -> str:
    """Readable ID of a public key, e.g. 'SHA256:x7Kq...' (same style as OpenSSH)."""
    if len(pub) != PUBLIC_KEY_SIZE:
        raise ValueError(f"public key must be {PUBLIC_KEY_SIZE} bytes, got {len(pub)}")
    digest = hashlib.sha256(pub).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def verify(pub: bytes, data: bytes, sig: bytes) -> bool:
    """True only if `sig` is a valid signature of `data` by `pub`. Never raises on bad signatures."""
    if len(pub) != PUBLIC_KEY_SIZE:
        raise ValueError(f"public key must be {PUBLIC_KEY_SIZE} bytes, got {len(pub)}")
    if len(sig) != SIGNATURE_SIZE:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, data)
    except InvalidSignature:
        return False
    return True

# ---------------------------------------------------------------- TrustStore

class TrustResult(Enum):
    NEW = "new"            # never seen this peer name
    TRUSTED = "trusted"    # known name, same key
    CHANGED = "changed"    # known name, DIFFERENT key (possible impersonation)


class TrustError(Exception):
    """Raised when a trust-store change would be unsafe."""


MAX_NAME_LENGTH = 255


def _validate_name(name) -> None:
    if not isinstance(name, str) or not (1 <= len(name) <= MAX_NAME_LENGTH):
        raise ValueError(f"peer name must be 1-{MAX_NAME_LENGTH} characters")


def _validate_pub(pub) -> None:
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != PUBLIC_KEY_SIZE:
        raise ValueError(f"public key must be {PUBLIC_KEY_SIZE} bytes")


class TrustStore:
    """Address book of trusted peers: {name: {fingerprint, pubkey_b64, first_seen}}."""

    def __init__(self, path=None):
        self.path = Path(path) if path else DEFAULT_DIR / "known_peers.json"
        self._lock = threading.Lock()

    # ---- file handling (callers must hold the lock) ----
    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("trust file is not a JSON object")
            return data
        except FileNotFoundError:
            return {}
        except ValueError:
            # Corrupted: keep a copy for inspection, start fresh (everyone becomes NEW).
            backup = self.path.with_name(self.path.name + ".corrupt")
            os.replace(self.path, backup)
            return {}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".known_peers.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)          # atomic swap
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def _matches(entry, pub: bytes) -> bool:
        try:
            stored = base64.b64decode(entry["pubkey_b64"], validate=True)
        except (KeyError, TypeError, ValueError):
            return False                         # malformed entry: never trust it
        return hmac.compare_digest(stored, bytes(pub))

    # ---- public API (the frozen interface) ----
    def check(self, peer_name: str, pub: bytes) -> TrustResult:
        _validate_name(peer_name)
        _validate_pub(pub)
        with self._lock:
            entry = self._load().get(peer_name)
        if entry is None:
            return TrustResult.NEW
        return TrustResult.TRUSTED if self._matches(entry, pub) else TrustResult.CHANGED

    def add(self, peer_name: str, pub: bytes) -> None:
        _validate_name(peer_name)
        _validate_pub(pub)
        with self._lock:
            data = self._load()
            existing = data.get(peer_name)
            if existing is not None:
                if self._matches(existing, pub):
                    return                       # already trusted, nothing to do
                raise TrustError(
                    f"'{peer_name}' is already trusted with a different key. "
                    f"Remove it first if you really want to replace it."
                )
            data[peer_name] = {
                "fingerprint": fingerprint(bytes(pub)),
                "pubkey_b64": base64.b64encode(bytes(pub)).decode(),
                "first_seen": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            self._save(data)

    def remove(self, peer_name: str) -> None:
        _validate_name(peer_name)
        with self._lock:
            data = self._load()
            if peer_name in data:
                del data[peer_name]
                self._save(data)

    def list_peers(self) -> dict:
        """For `p2pssh trust list`: {name: {fingerprint, first_seen}}."""
        with self._lock:
            data = self._load()
        return {
            name: {
                "fingerprint": entry.get("fingerprint", "?"),
                "first_seen": entry.get("first_seen", "?"),
            }
            for name, entry in data.items()
            if isinstance(entry, dict)
        }