class P2PSSHError(Exception):
    """Base class for all p2pssh errors."""

class FrameError(P2PSSHError):
    """Frame too large or malformed."""

class ConnectionClosed(P2PSSHError):
    """Peer disconnected or connection already closed."""