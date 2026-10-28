"""A.2 - Authenticated key-exchange handshake.  Wire format: docs/protocol.md.

    ClientHello  (97 B)  version | client_eph_pub | client_nonce | client_id_pub
    ServerHello  (161 B) version | server_eph_pub | server_nonce | server_id_pub | sig_server
    ClientAuth   (64 B)  sig_client

    sig_server = Sign(server_id, b"p2pssh v1 server" || H1)   H1 = SHA256(CH || SH_without_sig)
    sig_client = Sign(client_id, b"p2pssh v1 client" || H2)   H2 = SHA256(CH || SH)
    keys = HKDF-SHA256(X25519 shared, salt=SHA256(c_nonce||s_nonce), info="p2pssh v1", 64 bytes)

On any failure the connection is closed WITHOUT sending error details to the peer
(no plaintext error oracle before authentication).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import HANDSHAKE_TIMEOUT
from .errors import (
    E_AUTH,
    E_KEYCHANGED,
    E_PROTOCOL,
    E_TIMEOUT,
    E_VERSION,
    ConnectionClosed,
    ConnTimeout,
    FrameError,
    HandshakeError,
)
from .identity import fingerprint

VERSION = 1
CH_LEN, SH_LEN, AUTH_LEN = 97, 161, 64
PREFIX_SERVER = b"p2pssh v1 server"
PREFIX_CLIENT = b"p2pssh v1 client"
HKDF_INFO = b"p2pssh v1"
PROMPT_ALLOWANCE = 60.0   # extra seconds the responder waits while the peer's user answers a prompt


@dataclass
class SessionKeys:
    send_key: bytes = field(repr=False)     # never print keys
    recv_key: bytes = field(repr=False)
    peer_pub: bytes                         # peer's Ed25519 identity key (32 B)
    peer_fingerprint: str
    session_id: bytes                       # 16 B, not secret


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _raw(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _verify_sig(pub: bytes, sig: bytes, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def _derive(my_priv: X25519PrivateKey, peer_eph: bytes, c_nonce: bytes, s_nonce: bytes):
    try:
        shared = my_priv.exchange(X25519PublicKey.from_public_bytes(peer_eph))
    except ValueError:   # the library already refuses low-order points
        raise HandshakeError(E_AUTH, "invalid or low-order ephemeral key")
    if hmac.compare_digest(shared, bytes(32)):
        raise HandshakeError(E_AUTH, "low-order ephemeral key (all-zero shared secret)")
    salt = hashlib.sha256(c_nonce + s_nonce).digest()
    keys = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=HKDF_INFO).derive(shared)
    return keys[:32], keys[32:]          # c2s_key, s2c_key


class _Deadline:
    def __init__(self, seconds: float):
        self.end = time.monotonic() + seconds

    def extend(self, seconds: float) -> None:
        self.end += seconds

    def remaining(self) -> float:
        left = self.end - time.monotonic()
        if left <= 0:
            raise HandshakeError(E_TIMEOUT, "handshake timed out")
        return left


async def _recv(conn, dl: _Deadline) -> bytes:
    return await conn.recv_frame(timeout=dl.remaining())


def _verdict(result) -> str:
    """Works with an Enum (TrustResult.NEW) or a plain string ("NEW")."""
    text = getattr(result, "name", None) or str(result)
    return text.split(".")[-1].upper()


async def _check_trust(trust, name: str, pub: bytes, confirm) -> None:
    verdict = _verdict(trust.check(name, pub))
    if verdict == "TRUSTED":
        return
    if verdict == "CHANGED":                      # never auto-accepted
        raise HandshakeError(E_KEYCHANGED, f"the key for '{name}' has changed")
    if verdict != "NEW":
        raise HandshakeError(E_PROTOCOL, f"unexpected trust result {verdict!r}")
    await _ask_user(trust, name, pub, confirm)


async def _ask_user(trust, name: str, pub: bytes, confirm) -> None:
    """A NEW peer: ask the user. No callback or any error => reject (fail closed)."""
    accepted = False
    if confirm is not None:
        try:
            answer = confirm(fingerprint(pub), name)
            if inspect.isawaitable(answer):
                answer = await answer
            accepted = bool(answer)
        except Exception:
            accepted = False
    if not accepted:
        raise HandshakeError(E_AUTH, "peer was not trusted by the user")
    trust.add(name, pub)


async def _check_trust_by_fingerprint(trust, pub: bytes, confirm) -> None:
    """Responder side: the client has no stable name, so look it up by key fingerprint.

    TrustStore.find_by_fingerprint(fp) -> name | None  (None means NEW).
    A new key is stored under its own fingerprint string as the name.
    """
    fp = fingerprint(pub)
    finder = getattr(trust, "find_by_fingerprint", None)
    if finder is None:                            # older TrustStore: fall back to name = fingerprint
        await _check_trust(trust, fp, pub, confirm)
        return
    if finder(fp) is not None:                    # key is already in the store: TRUSTED
        return
    await _ask_user(trust, fp, pub, confirm)


# --------------------------------------------------------------------------
# public entry point (signature frozen in plan 4.5; allow_self etc. are optional)
# --------------------------------------------------------------------------
async def perform_handshake(
    conn,
    identity,
    trust,
    role: str,
    allow_self: bool = False,
    *,
    confirm: Optional[Callable] = None,
    timeout: float = HANDSHAKE_TIMEOUT,
    prompt_allowance: float = PROMPT_ALLOWANCE,
) -> SessionKeys:
    """Run the handshake. role is "initiator" or "responder". Raises HandshakeError.

    confirm(fingerprint, peer_name) -> bool (sync or async) is asked when a peer is NEW.
    Without it, NEW peers are rejected (fail closed).
    """
    if role not in ("initiator", "responder"):
        raise ValueError('role must be "initiator" or "responder"')
    try:
        if role == "initiator":
            return await _initiator(conn, identity, trust, allow_self, confirm, timeout)
        return await _responder(conn, identity, trust, allow_self, confirm, timeout, prompt_allowance)
    except HandshakeError:
        await _close(conn)
        raise
    except ConnTimeout as e:
        await _close(conn)
        raise HandshakeError(E_TIMEOUT, "handshake timed out") from e
    except (ConnectionClosed, FrameError) as e:
        await _close(conn)
        raise HandshakeError(E_PROTOCOL, "connection closed or bad frame during handshake") from e


async def _close(conn) -> None:
    try:
        await conn.close()
    except Exception:
        pass


# --------------------------------------------------------------------------
# initiator (client)
# --------------------------------------------------------------------------
async def _initiator(conn, identity, trust, allow_self, confirm, timeout) -> SessionKeys:
    dl = _Deadline(timeout)
    my_id = identity.public_bytes()
    eph = X25519PrivateKey.generate()
    eph_pub = _raw(eph.public_key())
    c_nonce = os.urandom(32)

    ch = bytes([VERSION]) + eph_pub + c_nonce + my_id
    await conn.send_frame(ch)

    sh = await _recv(conn, dl)
    if len(sh) != SH_LEN:
        raise HandshakeError(E_PROTOCOL, "bad ServerHello length")
    if sh[0] != VERSION:
        raise HandshakeError(E_VERSION, f"unsupported protocol version {sh[0]}")
    s_eph, s_nonce, s_id, sig_s = sh[1:33], sh[33:65], sh[65:97], sh[97:161]

    if s_eph == eph_pub or s_nonce == c_nonce:
        raise HandshakeError(E_PROTOCOL, "reflection detected")
    if s_id == my_id and not allow_self:
        raise HandshakeError(E_PROTOCOL, "refusing to connect to ourselves (use allow_self for tests)")

    h1 = hashlib.sha256(ch + sh[:97]).digest()
    if not _verify_sig(s_id, sig_s, PREFIX_SERVER + h1):
        raise HandshakeError(E_AUTH, "server signature is invalid")

    c2s, s2c = _derive(eph, s_eph, c_nonce, s_nonce)
    del eph

    name = getattr(conn, "peer_name", None) or fingerprint(s_id)
    await _check_trust(trust, name, s_id, confirm)      # may wait for the user: no network wait here

    h2 = hashlib.sha256(ch + sh).digest()
    await conn.send_frame(identity.sign(PREFIX_CLIENT + h2))
    return SessionKeys(c2s, s2c, s_id, fingerprint(s_id), h2[:16])


# --------------------------------------------------------------------------
# responder (server)
# --------------------------------------------------------------------------
async def _responder(conn, identity, trust, allow_self, confirm, timeout, prompt_allowance) -> SessionKeys:
    dl = _Deadline(timeout)
    my_id = identity.public_bytes()
    eph = X25519PrivateKey.generate()
    eph_pub = _raw(eph.public_key())
    s_nonce = os.urandom(32)

    ch = await _recv(conn, dl)
    if len(ch) != CH_LEN:
        raise HandshakeError(E_PROTOCOL, "bad ClientHello length")
    if ch[0] != VERSION:
        raise HandshakeError(E_VERSION, f"unsupported protocol version {ch[0]}")
    c_eph, c_nonce, c_id = ch[1:33], ch[33:65], ch[65:97]

    if c_eph == eph_pub or c_nonce == s_nonce:
        raise HandshakeError(E_PROTOCOL, "reflection detected")
    if c_id == my_id and not allow_self:
        raise HandshakeError(E_PROTOCOL, "refusing to connect to ourselves (use allow_self for tests)")

    sh_nosig = bytes([VERSION]) + eph_pub + s_nonce + my_id
    h1 = hashlib.sha256(ch + sh_nosig).digest()
    sh = sh_nosig + identity.sign(PREFIX_SERVER + h1)
    await conn.send_frame(sh)

    # The client may be showing its user a "trust this server?" prompt right now.
    dl.extend(prompt_allowance)
    auth = await _recv(conn, dl)
    if len(auth) != AUTH_LEN:
        raise HandshakeError(E_PROTOCOL, "bad ClientAuth length")

    h2 = hashlib.sha256(ch + sh).digest()
    if not _verify_sig(c_id, auth, PREFIX_CLIENT + h2):
        raise HandshakeError(E_AUTH, "client signature is invalid")

    c2s, s2c = _derive(eph, c_eph, c_nonce, s_nonce)
    del eph

    # The responder has no stable name for the client: look it up by fingerprint.
    await _check_trust_by_fingerprint(trust, c_id, confirm)
    return SessionKeys(s2c, c2s, c_id, fingerprint(c_id), h2[:16])