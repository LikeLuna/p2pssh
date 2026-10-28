class P2PSSHError(Exception):
    """Base class for all p2pssh errors."""

class FrameError(P2PSSHError):
    """Frame too large or malformed."""

class ConnectionClosed(P2PSSHError):
    """Peer disconnected or connection already closed."""

class ConnTimeout(P2PSSHError):
    """No data arrived within the allowed time."""



# ---- error codes (plan section 4.6) ----
E_VERSION = 1
E_AUTH = 2
E_KEYCHANGED = 3
E_DECRYPT = 4
E_REPLAY = 5
E_FRAME = 6
E_TIMEOUT = 7
E_PROTOCOL = 8


class HandshakeError(P2PSSHError):
    """Handshake failed. `.code` is one of the E_* codes above."""

    def __init__(self, code: int, message: str = ""):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message